// Package sampler takes the 10 s resource samples (design §6.4, §6.5, §7):
// the probe, every WmiPrvSE (separately, by PID and create time) and the
// Winmgmt host, plus host CPU, memory, disk and the contention canary. It
// uses native APIs only.
package sampler

import (
	"fmt"
	"hash/fnv"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"wmiresearch/probe/internal/sysinfo"
)

// key identifies a process instance (PIDs are reused).
type key struct {
	pid    uint32
	create int64
}

type modInfo struct {
	hash string
	list []string
	at   time.Time
}

// Sampler keeps state between samples.
type Sampler struct {
	self       uint32
	numCPU     int
	diskPath   string
	classDLL   map[string]string // class -> provider DLL (lower case), from pre-flight
	modRefresh time.Duration

	prevT    time.Time
	prevSys  sysinfo.CPUTimes
	prevCPU  map[key]int64
	acct     map[key]string
	mods     map[key]modInfo
	wmiprvse map[key]bool
	exits    int
	svcAt    time.Time
	svcHost  string
	svcPID   uint32
}

// New returns a sampler. classDLL may be nil (no attribution).
func New(diskPath string, classDLL map[string]string) *Sampler {
	return &Sampler{
		self: uint32(os.Getpid()), numCPU: runtime.NumCPU(), diskPath: diskPath, classDLL: classDLL,
		modRefresh: time.Minute, prevCPU: map[key]int64{}, acct: map[key]string{}, mods: map[key]modInfo{},
		wmiprvse: map[key]bool{},
	}
}

// Sample is one sample's results.
type Sample struct {
	Time       time.Time
	Snap       sysinfo.Snapshot
	ProcRows   [][]string
	Events     [][]string // ts, kind, slot, conn_id, pid, detail
	HostCPU    float64
	InducedCPU float64 // probe + all WmiPrvSE + Winmgmt host, % of all CPUs
	Mem        sysinfo.Memory
	DiskFreeGB float64
	Canary     time.Duration
	WmiPrvSE   int
	Exits      int
	Winmgmt    sysinfo.Proc
	WinmgmtOK  bool
	Probe      sysinfo.Proc
	ClassHost  map[string]uint32 // class -> WmiPrvSE PID serving it
	Err        error
}

// Sample takes one sample.
func (s *Sampler) Sample() Sample {
	now := time.Now().UTC()
	out := Sample{Time: now, ClassHost: map[string]uint32{}}
	ts := now.Format(time.RFC3339Nano)
	out.Canary = sysinfo.Canary()

	snap, err := sysinfo.ProcessSnapshot()
	if err != nil {
		out.Err = err
		return out
	}
	out.Snap = snap
	sysT, _ := sysinfo.SystemTimes()
	out.Mem, _ = sysinfo.MemoryStatus()
	if free, err := sysinfo.DiskFree(s.diskPath); err == nil {
		out.DiskFreeGB = float64(free) / (1 << 30)
	}

	// Winmgmt host: PID from the SCM; services sharing it every minute.
	if pid, err := sysinfo.ServicePID("Winmgmt"); err == nil && pid != 0 {
		if pid != s.svcPID || now.Sub(s.svcAt) > time.Minute {
			names, _ := sysinfo.ServicesInProcess(pid)
			sort.Strings(names)
			s.svcHost, s.svcPID, s.svcAt = strings.Join(names, ";"), pid, now
		}
		out.Winmgmt, out.WinmgmtOK = snap[pid]
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	dt := now.Sub(s.prevT)
	induced := int64(0)
	seen := map[key]bool{}
	row := func(role string, p sysinfo.Proc, label, modHash, svc string, goStats bool) {
		k := key{p.PID, p.Create}
		cpu := p.KernelTime + p.UserTime
		if prev, ok := s.prevCPU[k]; ok && !s.prevT.IsZero() {
			induced += cpu - prev
		}
		s.prevCPU[k] = cpu
		seen[k] = true
		acct, ok := s.acct[k]
		if !ok {
			acct, _ = sysinfo.Account(p.PID)
			s.acct[k] = acct
		}
		r := []string{ts, role, u(p.PID), ftime(p.Create), p.Name, acct, label,
			u64(p.Private), u64(p.WorkingSet), u(p.Handles), u(p.Threads),
			strconv.FormatInt(p.KernelTime/10000, 10), strconv.FormatInt(p.UserTime/10000, 10),
			"", "", "", "", modHash, svc}
		if goStats {
			r[13], r[14] = u64(ms.HeapAlloc), u64(ms.HeapSys)
			r[15], r[16] = strconv.Itoa(runtime.NumGoroutine()), u(ms.NumGC)
		}
		out.ProcRows = append(out.ProcRows, r)
	}

	if p, ok := snap[s.self]; ok {
		out.Probe = p
		row("probe", p, "", "", "", true)
	}
	if out.WinmgmtOK {
		row("winmgmt_host", out.Winmgmt, "", "", s.svcHost, false)
	}
	current := map[key]bool{}
	for _, p := range snap.ByName("WmiPrvSE.exe") {
		k := key{p.PID, p.Create}
		current[k] = true
		if !s.wmiprvse[k] {
			out.Events = append(out.Events, []string{ts, "wmiprvse_start", "", "", u(p.PID), "create " + ftime(p.Create)})
		}
		mi := s.mods[k]
		if mi.at.IsZero() || now.Sub(mi.at) >= s.modRefresh {
			if list, err := sysinfo.Modules(p.PID); err == nil {
				sort.Strings(list)
				h := hashList(list)
				if h != mi.hash {
					out.Events = append(out.Events, []string{ts, "wmiprvse_modules", "", "", u(p.PID), strings.Join(list, "|")})
				}
				mi = modInfo{hash: h, list: list, at: now}
			} else {
				mi.at = now
			}
			s.mods[k] = mi
		}
		label := s.label(k, mi.list)
		for class, dll := range s.classDLL {
			if contains(mi.list, dll) {
				out.ClassHost[class] = p.PID
			}
		}
		row("wmiprvse", p, label, mi.hash, "", false)
		out.WmiPrvSE++
	}
	for k := range s.wmiprvse {
		if !current[k] {
			s.exits++
			out.Events = append(out.Events, []string{ts, "wmiprvse_exit", "", "", u(k.pid), "create " + ftime(k.create)})
			delete(s.mods, k)
		}
	}
	s.wmiprvse = current
	out.Exits = s.exits

	for k := range s.prevCPU {
		if !seen[k] {
			delete(s.prevCPU, k)
			delete(s.acct, k)
		}
	}
	if !s.prevT.IsZero() && dt > 0 {
		out.HostCPU = sysinfo.BusyPct(s.prevSys, sysT)
		out.InducedCPU = 100 * float64(induced) / (float64(dt/100) * float64(s.numCPU))
	}
	s.prevT, s.prevSys = now, sysT
	return out
}

// label is the WmiPrvSE's account plus the provider DLLs from the catalog's
// attribution map that it has loaded.
func (s *Sampler) label(k key, mods []string) string {
	var hits []string
	for _, dll := range s.classDLL {
		if contains(mods, dll) && !contains(hits, dll) {
			hits = append(hits, dll)
		}
	}
	sort.Strings(hits)
	return s.acct[k] + "|" + strings.Join(hits, "+")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hashList(list []string) string {
	h := fnv.New32a()
	for _, s := range list {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%08x", h.Sum32())
}

func u[T ~uint32](v T) string { return strconv.FormatUint(uint64(v), 10) }
func u64(v uint64) string     { return strconv.FormatUint(v, 10) }

// ftime formats a FILETIME as RFC 3339 UTC.
func ftime(ft int64) string {
	if ft == 0 {
		return ""
	}
	return time.Unix(0, (ft-116444736000000000)*100).UTC().Format(time.RFC3339Nano)
}

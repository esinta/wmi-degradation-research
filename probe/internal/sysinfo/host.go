package sysinfo

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"wmiresearch/probe/internal/clock"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// CPUTimes are the system-wide idle, kernel (includes idle) and user times,
// in 100 ns units.
type CPUTimes struct{ Idle, Kernel, User int64 }

// SystemTimes calls GetSystemTimes.
func SystemTimes() (CPUTimes, error) {
	var i, k, u windows.Filetime
	r, _, err := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	if r == 0 {
		return CPUTimes{}, err
	}
	ft := func(f windows.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	return CPUTimes{ft(i), ft(k), ft(u)}, nil
}

// BusyPct is the share of non-idle CPU between two samples, in percent of
// all CPUs.
func BusyPct(a, b CPUTimes) float64 {
	total := (b.Kernel - a.Kernel) + (b.User - a.User)
	if total <= 0 {
		return 0
	}
	busy := total - (b.Idle - a.Idle)
	return 100 * float64(busy) / float64(total)
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// Memory is physical memory and commit, in bytes.
type Memory struct {
	TotalPhys, AvailPhys     uint64
	CommitLimit, CommitTotal uint64
}

// MemoryStatus calls GlobalMemoryStatusEx. Commit limit is ullTotalPageFile;
// commit charge is limit minus ullAvailPageFile.
func MemoryStatus() (Memory, error) {
	m := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return Memory{}, err
	}
	return Memory{TotalPhys: m.TotalPhys, AvailPhys: m.AvailPhys, CommitLimit: m.TotalPageFile, CommitTotal: m.TotalPageFile - m.AvailPageFile}, nil
}

// DiskFree returns the free bytes available on the volume holding path.
func DiskFree(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}

var canaryBuf = make([]byte, 64<<10)

// Canary times a fixed CPU workload (16 SHA-256 passes over 64 KiB). It does
// not touch WMI or the disk; when it slows down, the host (or hypervisor) is
// contended, and latency changes are environmental (design §5.4).
func Canary() time.Duration {
	t0 := clock.Now()
	var sum [32]byte
	for range 16 {
		sum = sha256.Sum256(canaryBuf)
		canaryBuf[0] = sum[0]
	}
	return clock.Since(t0)
}

// OSInfo describes the host for meta.json.
type OSInfo struct {
	Hostname    string `json:"hostname"`
	ProductName string `json:"product_name"`
	Build       string `json:"build"` // major.minor.build.UBR
	NumCPU      int    `json:"num_cpu"`
	TotalPhysMB uint64 `json:"total_phys_mb"`
}

// GetOSInfo reads RtlGetVersion and the UBR from the registry.
func GetOSInfo(numCPU int) OSInfo {
	v := windows.RtlGetVersion()
	info := OSInfo{NumCPU: numCPU}
	info.Hostname, _ = os.Hostname()
	ubr := uint64(0)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		info.ProductName, _, _ = k.GetStringValue("ProductName")
		ubr, _, _ = k.GetIntegerValue("UBR")
		k.Close()
	}
	info.Build = fmt.Sprintf("%d.%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber, ubr)
	if m, err := MemoryStatus(); err == nil {
		info.TotalPhysMB = m.TotalPhys >> 20
	}
	return info
}

// Registry cross-check counts for invariant ground truth (design §6.6).
const (
	RegFirewallRules = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`
	RegTaskCache     = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
)

// RegistryCount returns the value count ("fwrules": firewall rules in the
// local store) or the subkey count ("tasks": registered tasks).
func RegistryCount(which string) (int, error) {
	path := map[string]string{"fwrules": RegFirewallRules, "tasks": RegTaskCache}[strings.ToLower(which)]
	if path == "" {
		return 0, fmt.Errorf("unknown registry count %q", which)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	st, err := k.Stat()
	if err != nil {
		return 0, err
	}
	if which == "fwrules" {
		return int(st.ValueCount), nil
	}
	return int(st.SubKeyCount), nil
}

// CLSIDServer returns the lower-case base name of a COM class's
// InprocServer32 DLL (provider attribution, design §7).
func CLSIDServer(clsid string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`+clsid+`\InprocServer32`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("")
	if err != nil {
		return "", err
	}
	if exp, err := registry.ExpandString(v); err == nil {
		v = exp
	}
	v = strings.Trim(v, `"`)
	if i := strings.LastIndexAny(v, `\/`); i >= 0 {
		v = v[i+1:]
	}
	return strings.ToLower(v), nil
}

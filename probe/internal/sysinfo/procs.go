// Package sysinfo reads processes, services, host resources and registry
// counts through native APIs. It never uses WMI: the old probe sampled
// WmiPrvSE through WMI, on a connection that was itself under test.
package sysinfo

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Proc is one process from a SystemProcessInformation snapshot.
type Proc struct {
	PID, PPID  uint32
	Create     int64 // FILETIME, 100 ns since 1601 (UTC)
	Name       string
	Threads    uint32
	Handles    uint32
	Private    uint64 // PrivatePageCount (bytes): private committed memory
	WorkingSet uint64
	KernelTime int64 // 100 ns
	UserTime   int64 // 100 ns
}

// Snapshot is a whole-system process list, keyed by PID.
type Snapshot map[uint32]Proc

// ProcessSnapshot takes one NtQuerySystemInformation(SystemProcessInformation)
// snapshot: PID, create time, private bytes, working set, handles, threads
// and CPU times for every process in a single call.
func ProcessSnapshot() (Snapshot, error) {
	size := uint32(512 << 10)
	for range 8 {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&buf[0]), size, &ret)
		if errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			size = max(ret, size) * 2
			continue
		}
		if err != nil {
			return nil, err
		}
		return parse(buf[:max(ret, 1)]), nil
	}
	return nil, errors.New("process snapshot: buffer kept growing")
}

func parse(buf []byte) Snapshot {
	s := make(Snapshot, 256)
	off := uint32(0)
	for {
		if int(off)+int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{})) > len(buf) {
			return s
		}
		p := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buf[off]))
		name := ""
		if p.ImageName.Buffer != nil && p.ImageName.Length > 0 {
			name = windows.UTF16ToString(unsafe.Slice(p.ImageName.Buffer, p.ImageName.Length/2))
		} else if p.UniqueProcessID == 0 {
			name = "System Idle Process"
		}
		pid := uint32(p.UniqueProcessID)
		s[pid] = Proc{
			PID: pid, PPID: uint32(p.InheritedFromUniqueProcessID), Create: p.CreateTime, Name: name,
			Threads: p.NumberOfThreads, Handles: p.HandleCount, Private: uint64(p.PrivatePageCount),
			WorkingSet: uint64(p.WorkingSetSize), KernelTime: p.KernelTime, UserTime: p.UserTime,
		}
		if p.NextEntryOffset == 0 {
			return s
		}
		off += p.NextEntryOffset
	}
}

// ByName returns the processes whose image name matches (case-insensitive).
func (s Snapshot) ByName(name string) []Proc {
	var out []Proc
	for _, p := range s {
		if strings.EqualFold(p.Name, name) {
			out = append(out, p)
		}
	}
	return out
}

// CreateTime returns a live process's create time (FILETIME), or ok=false
// when it cannot be opened (exited, or access denied).
func CreateTime(pid uint32) (create int64, ok bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, false
	}
	var code uint32
	if windows.GetExitCodeProcess(h, &code) == nil && code != 259 { // STILL_ACTIVE
		return 0, false
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime), true
}

// Modules returns the base names (lower case) of the modules loaded in pid.
func Modules(pid uint32) ([]string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	mods := make([]windows.Handle, 512)
	for range 4 {
		var need uint32
		if err := windows.EnumProcessModulesEx(h, &mods[0], uint32(len(mods))*uint32(unsafe.Sizeof(mods[0])), &need, windows.LIST_MODULES_ALL); err != nil {
			return nil, err
		}
		n := int(need / uint32(unsafe.Sizeof(mods[0])))
		if n > len(mods) {
			mods = make([]windows.Handle, n+64)
			continue
		}
		out := make([]string, 0, n)
		var name [windows.MAX_PATH]uint16
		for _, m := range mods[:n] {
			if windows.GetModuleBaseName(h, m, &name[0], uint32(len(name))) == nil {
				out = append(out, strings.ToLower(windows.UTF16ToString(name[:])))
			}
		}
		return out, nil
	}
	return nil, errors.New("module list kept growing")
}

// Account returns DOMAIN\user of the process's token.
func Account(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	acct, dom, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String(), nil
	}
	return dom + `\` + acct, nil
}

package truth

import (
	"strings"

	"golang.org/x/sys/windows"

	"wmiresearch/probe/internal/sysinfo"
)

// Native reads truth from the OS: NtQuerySystemInformation, OpenProcess,
// the SCM and the registry.
type Native struct{}

func (Native) Snapshot() (sysinfo.Snapshot, error)     { return sysinfo.ProcessSnapshot() }
func (Native) CreateTime(pid uint32) (int64, bool)     { return sysinfo.CreateTime(pid) }
func (Native) RegistryCount(which string) (int, error) { return sysinfo.RegistryCount(which) }

func (Native) ServiceNames(drivers bool) (map[string]bool, error) {
	typ := uint32(windows.SERVICE_WIN32)
	if drivers {
		typ = windows.SERVICE_DRIVER
	}
	svcs, err := sysinfo.Services(typ)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(svcs))
	for _, s := range svcs {
		m[strings.ToLower(s.Name)] = true
	}
	return m, nil
}

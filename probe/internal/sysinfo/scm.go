package sysinfo

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Service is one SCM entry.
type Service struct {
	Name  string
	PID   uint32
	State uint32
	Type  uint32
}

func openSCM() (windows.Handle, error) {
	return windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
}

// Services enumerates services of the given type (windows.SERVICE_WIN32 or
// windows.SERVICE_DRIVER), in any state.
func Services(serviceType uint32) ([]Service, error) {
	m, err := openSCM()
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(m)
	var need, count, resume uint32
	buf := make([]byte, 64<<10)
	var out []Service
	for {
		err := windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, serviceType, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &need, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, err
		}
		entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
		for _, e := range entries {
			out = append(out, Service{
				Name:  windows.UTF16PtrToString(e.ServiceName),
				PID:   e.ServiceStatusProcess.ProcessId,
				State: e.ServiceStatusProcess.CurrentState,
				Type:  e.ServiceStatusProcess.ServiceType,
			})
		}
		if err == nil {
			return out, nil
		}
		if need > uint32(len(buf)) {
			buf = make([]byte, need)
		}
	}
}

// ServicePID returns the PID of a running service (0 when stopped).
func ServicePID(name string) (uint32, error) {
	m, err := openSCM()
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(m)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0, err
	}
	return st.ProcessId, nil
}

// ServicesInProcess returns the names of the running Win32 services hosted
// by pid (the Winmgmt svchost check, design §7).
func ServicesInProcess(pid uint32) ([]string, error) {
	all, err := Services(windows.SERVICE_WIN32)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range all {
		if s.PID == pid && pid != 0 {
			out = append(out, s.Name)
		}
	}
	return out, nil
}

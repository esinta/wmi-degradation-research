// Package fault injects the E-fault faults (design §4.1, E-fault): kill the
// WmiPrvSE serving the probe's classes, and restart the Winmgmt service.
// It uses no WMI: TerminateProcess and the service control manager.
package fault

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Native is the production injector.
type Native struct{}

// KillHost terminates a provider host. WMI starts a new one on the next
// call that needs it.
func (Native) KillHost(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return fmt.Errorf("image of %d: %w", pid, err)
	}
	if img := windows.UTF16ToString(buf[:size]); !strings.EqualFold(img[strings.LastIndex(img, `\`)+1:], "WmiPrvSE.exe") {
		return fmt.Errorf("pid %d is %s, not WmiPrvSE.exe", pid, img)
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("TerminateProcess %d: %w", pid, err)
	}
	return nil
}

// RestartWinmgmt stops the services that depend on Winmgmt and are running,
// stops Winmgmt, starts it again, then starts those dependents again. The
// report lists what was stopped and restarted, with timings.
func (Native) RestartWinmgmt() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService("Winmgmt")
	if err != nil {
		return "", err
	}
	defer s.Close()

	// EnumDependentServices returns dependents in reverse start order, which
	// is the order to stop them in.
	deps, err := s.ListDependentServices(svc.Active)
	if err != nil {
		return "", fmt.Errorf("dependents: %w", err)
	}
	for _, d := range deps {
		if strings.EqualFold(d, "EsintaEndpoints") {
			// Project rule: the probe never touches the Esinta service.
			return "", fmt.Errorf("EsintaEndpoints is running and depends on Winmgmt: not restarting")
		}
	}
	var rep []string
	t0 := time.Now()
	for _, d := range deps {
		if err := stop(m, d, 60*time.Second); err != nil {
			return strings.Join(rep, "; "), fmt.Errorf("stop dependent %s: %w", d, err)
		}
		rep = append(rep, "stopped "+d)
	}
	if err := stop(m, "Winmgmt", 60*time.Second); err != nil {
		return strings.Join(rep, "; "), fmt.Errorf("stop Winmgmt: %w", err)
	}
	rep = append(rep, fmt.Sprintf("Winmgmt stopped after %s", time.Since(t0).Round(time.Millisecond)))
	t1 := time.Now()
	if err := start(m, "Winmgmt", 60*time.Second); err != nil {
		return strings.Join(rep, "; "), fmt.Errorf("start Winmgmt: %w", err)
	}
	rep = append(rep, fmt.Sprintf("Winmgmt running after %s", time.Since(t1).Round(time.Millisecond)))
	var errs []string
	for i := len(deps) - 1; i >= 0; i-- {
		if err := start(m, deps[i], 60*time.Second); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", deps[i], err))
			continue
		}
		rep = append(rep, "restarted "+deps[i])
	}
	if len(errs) > 0 {
		return strings.Join(rep, "; "), fmt.Errorf("restart dependents: %s", strings.Join(errs, "; "))
	}
	return strings.Join(rep, "; "), nil
}

func stop(m *mgr.Mgr, name string, timeout time.Duration) error {
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
	}
	return wait(s, svc.Stopped, timeout)
}

func start(m *mgr.Mgr, name string, timeout time.Duration) error {
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Running && st.State != svc.StartPending {
		if err := s.Start(); err != nil {
			return err
		}
	}
	return wait(s, svc.Running, timeout)
}

func wait(s *mgr.Service, want svc.State, timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("state %d after %s, want %d", st.State, timeout, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

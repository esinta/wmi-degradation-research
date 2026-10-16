package sysinfo

import (
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// Native API reads only; no WMI.

func TestProcessSnapshotFindsSelf(t *testing.T) {
	s, err := ProcessSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	self, ok := s[uint32(os.Getpid())]
	if !ok {
		t.Fatalf("own PID missing from %d processes", len(s))
	}
	if self.Threads == 0 || self.Handles == 0 || self.Private == 0 || self.Create == 0 || self.Name == "" {
		t.Fatalf("self entry incomplete: %+v", self)
	}
	c, ok := CreateTime(uint32(os.Getpid()))
	if !ok || c != self.Create {
		t.Fatalf("CreateTime %d ok %v, snapshot %d", c, ok, self.Create)
	}
	if _, ok := s[4]; !ok {
		t.Error("System (PID 4) missing")
	}
}

func TestCreateTimeOfMissingPID(t *testing.T) {
	if _, ok := CreateTime(0xFFFFFFF0); ok {
		t.Fatal("bogus PID reported alive")
	}
}

func TestHostCounters(t *testing.T) {
	a, err := SystemTimes()
	if err != nil {
		t.Fatal(err)
	}
	Canary()
	b, _ := SystemTimes()
	if p := BusyPct(a, b); p < 0 || p > 100 {
		t.Fatalf("busy %g", p)
	}
	m, err := MemoryStatus()
	if err != nil || m.TotalPhys == 0 || m.CommitLimit < m.CommitTotal {
		t.Fatalf("memory %+v err %v", m, err)
	}
	if _, err := DiskFree(os.TempDir()); err != nil {
		t.Fatal(err)
	}
	if info := GetOSInfo(runtime.NumCPU()); info.Build == "" || info.NumCPU == 0 {
		t.Fatalf("os info %+v", info)
	}
}

func TestServices(t *testing.T) {
	svcs, err := Services(windows.SERVICE_WIN32)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) < 20 {
		t.Fatalf("only %d services", len(svcs))
	}
	pid, err := ServicePID("Winmgmt")
	if err != nil {
		t.Fatal(err)
	}
	if pid != 0 {
		names, err := ServicesInProcess(pid)
		if err != nil || len(names) == 0 {
			t.Fatalf("Winmgmt host %d: %v %v", pid, names, err)
		}
	}
}

func TestModulesOfSelf(t *testing.T) {
	mods, err := Modules(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range mods {
		if m == "kernel32.dll" {
			found = true
		}
	}
	if !found {
		t.Fatalf("kernel32.dll not in %v", mods)
	}
}

package abort

import (
	"strings"
	"testing"
	"time"
)

func healthy() Input {
	return Input{AvailPhysPct: 50, AvailPhysMB: 4000, CommitPct: 40, HostCPUPct: 30, InducedCPUPct: 20,
		DiskFreeGB: 50, WinmgmtPrivateMB: 30, WinmgmtHandles: 2000, WmiPrvSE: 3, ProbePrivateMB: 40,
		ProbeHandles: 300, Goroutines: 50, Scheduled: 10000}
}

func TestHealthyNeverAborts(t *testing.T) {
	c := New(Defaults())
	now := time.Now()
	for i := range 100 {
		if r := c.Check(now.Add(time.Duration(i)*10*time.Second), healthy()); r != "" {
			t.Fatal(r)
		}
	}
}

func TestNeedsConsecutiveSamples(t *testing.T) {
	c := New(Defaults())
	now := time.Now()
	bad := healthy()
	bad.AvailPhysMB = 100
	for i := range 2 {
		if r := c.Check(now, bad); r != "" {
			t.Fatalf("aborted at sample %d: %s", i+1, r)
		}
	}
	if c.Check(now, healthy()) != "" {
		t.Fatal("healthy aborted")
	}
	c.Check(now, bad)
	c.Check(now, bad)
	if r := c.Check(now, bad); !strings.Contains(r, "physical memory") {
		t.Fatalf("got %q", r)
	}
}

func TestCPUMustBeSustained(t *testing.T) {
	c := New(Defaults())
	now := time.Now()
	hot := healthy()
	hot.HostCPUPct = 95
	for i := range 60 { // 9 min 50 s
		if r := c.Check(now.Add(time.Duration(i)*10*time.Second), hot); r != "" {
			t.Fatalf("aborted at sample %d: %s", i, r)
		}
	}
	if r := c.Check(now.Add(10*time.Minute), hot); !strings.Contains(r, "host_cpu") {
		t.Fatalf("got %q", r)
	}
}

func TestScheduleDrops(t *testing.T) {
	c := New(Defaults())
	in := healthy()
	in.Dropped = 200 // 2 %
	for range 2 {
		c.Check(time.Now(), in)
	}
	if r := c.Check(time.Now(), in); !strings.Contains(r, "not sustainable") {
		t.Fatalf("got %q", r)
	}
}

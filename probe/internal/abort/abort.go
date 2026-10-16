// Package abort implements the hard abort thresholds (design §9). A
// condition must hold for Consecutive samples in a row (CPU: for Sustained)
// before it aborts the arm. WmiPrvSE quota kills, restarts, query errors and
// silent failures are outcomes, never aborts.
package abort

import (
	"fmt"
	"time"
)

// Limits are the thresholds.
type Limits struct {
	MinAvailPhysPct      float64 // < this % of physical memory available
	MinAvailPhysMB       float64 // or < this many MB
	MaxCommitPct         float64
	MaxHostCPUPct        float64
	MaxInducedCPUPct     float64
	Sustained            time.Duration // for the CPU conditions
	MinDiskFreeGB        float64
	MaxWinmgmtPrivateMB  float64
	MaxWinmgmtHandles    float64
	MaxWmiPrvSE          int
	MaxProbePrivateMB    float64
	MaxProbeHandles      float64
	MaxGoroutines        int
	MaxSchedDroppedRatio float64 // dropped / scheduled, after MinScheduled
	MinScheduled         uint64
	Consecutive          int
}

// Defaults are the design's thresholds.
func Defaults() Limits {
	return Limits{
		MinAvailPhysPct: 10, MinAvailPhysMB: 400, MaxCommitPct: 90,
		MaxHostCPUPct: 90, MaxInducedCPUPct: 50, Sustained: 10 * time.Minute,
		MinDiskFreeGB: 5, MaxWinmgmtPrivateMB: 1024, MaxWinmgmtHandles: 50000,
		MaxWmiPrvSE: 24, MaxProbePrivateMB: 512, MaxProbeHandles: 10000, MaxGoroutines: 10000,
		MaxSchedDroppedRatio: 0.01, MinScheduled: 1000, Consecutive: 3,
	}
}

// Input is one sample.
type Input struct {
	AvailPhysPct, AvailPhysMB float64
	CommitPct                 float64
	HostCPUPct, InducedCPUPct float64
	DiskFreeGB                float64
	WinmgmtPrivateMB          float64
	WinmgmtHandles            float64
	WmiPrvSE                  int
	ProbePrivateMB            float64
	ProbeHandles              float64
	Goroutines                int
	Scheduled, Dropped        uint64
}

// Checker keeps the streaks between samples.
type Checker struct {
	L       Limits
	streak  map[string]int
	cpuHigh map[string]time.Time
}

// New returns a checker.
func New(l Limits) *Checker {
	return &Checker{L: l, streak: map[string]int{}, cpuHigh: map[string]time.Time{}}
}

// Check returns a non-empty reason when the arm must abort.
func (c *Checker) Check(now time.Time, in Input) string {
	l := c.L
	conds := []struct {
		name string
		bad  bool
		desc string
	}{
		{"memory", in.AvailPhysPct < l.MinAvailPhysPct || in.AvailPhysMB < l.MinAvailPhysMB,
			fmt.Sprintf("available physical memory %.0f MB (%.1f %%)", in.AvailPhysMB, in.AvailPhysPct)},
		{"commit", in.CommitPct > l.MaxCommitPct, fmt.Sprintf("commit charge %.1f %% of limit", in.CommitPct)},
		{"disk", in.DiskFreeGB < l.MinDiskFreeGB, fmt.Sprintf("results volume %.1f GB free", in.DiskFreeGB)},
		{"winmgmt", in.WinmgmtPrivateMB > l.MaxWinmgmtPrivateMB || in.WinmgmtHandles > l.MaxWinmgmtHandles,
			fmt.Sprintf("Winmgmt host %.0f MB private, %.0f handles", in.WinmgmtPrivateMB, in.WinmgmtHandles)},
		{"wmiprvse", in.WmiPrvSE > l.MaxWmiPrvSE, fmt.Sprintf("%d WmiPrvSE instances", in.WmiPrvSE)},
		{"probe", in.ProbePrivateMB > l.MaxProbePrivateMB || in.ProbeHandles > l.MaxProbeHandles || in.Goroutines > l.MaxGoroutines,
			fmt.Sprintf("probe %.0f MB private, %.0f handles, %d goroutines", in.ProbePrivateMB, in.ProbeHandles, in.Goroutines)},
		{"schedule", in.Scheduled >= l.MinScheduled && float64(in.Dropped) > l.MaxSchedDroppedRatio*float64(in.Scheduled),
			fmt.Sprintf("%d of %d scheduled queries dropped: the rate is not sustainable", in.Dropped, in.Scheduled)},
	}
	for _, cd := range conds {
		if !cd.bad {
			c.streak[cd.name] = 0
			continue
		}
		c.streak[cd.name]++
		if c.streak[cd.name] >= l.Consecutive {
			return cd.desc
		}
	}
	for _, cpu := range []struct {
		name   string
		v, max float64
	}{{"host_cpu", in.HostCPUPct, l.MaxHostCPUPct}, {"induced_cpu", in.InducedCPUPct, l.MaxInducedCPUPct}} {
		if cpu.v <= cpu.max {
			delete(c.cpuHigh, cpu.name)
			continue
		}
		since, ok := c.cpuHigh[cpu.name]
		if !ok {
			c.cpuHigh[cpu.name] = now
			continue
		}
		if now.Sub(since) >= l.Sustained {
			return fmt.Sprintf("%s above %.0f %% for %s", cpu.name, cpu.max, l.Sustained)
		}
	}
	return ""
}

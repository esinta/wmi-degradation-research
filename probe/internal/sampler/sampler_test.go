package sampler

import (
	"os"
	"testing"
	"time"

	"wmiresearch/probe/internal/out"
)

// Native reads only; no WMI.
func TestTwoSamples(t *testing.T) {
	s := New(os.TempDir(), nil)
	a := s.Sample()
	if a.Err != nil {
		t.Fatal(a.Err)
	}
	if a.Probe.PID == 0 || len(a.ProcRows) == 0 {
		t.Fatalf("no probe row: %+v", a.Probe)
	}
	for _, r := range a.ProcRows {
		if len(r) != len(out.ProcCols) {
			t.Fatalf("proc row has %d columns, schema %d", len(r), len(out.ProcCols))
		}
	}
	time.Sleep(200 * time.Millisecond)
	b := s.Sample()
	if b.HostCPU < 0 || b.HostCPU > 100 || b.InducedCPU < 0 {
		t.Fatalf("cpu host %g induced %g", b.HostCPU, b.InducedCPU)
	}
	if b.Mem.TotalPhys == 0 || b.DiskFreeGB <= 0 || b.Canary <= 0 {
		t.Fatalf("host fields: %+v %g %v", b.Mem, b.DiskFreeGB, b.Canary)
	}
}

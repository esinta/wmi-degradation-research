package sta

import "testing"

// These tests initialize COM apartments only; they create no WMI objects.

func TestThreadIsSTAAndStable(t *testing.T) {
	th, err := New(ModeSTA)
	if err != nil {
		t.Fatal(err)
	}
	defer th.Stop()
	for i := range 3 {
		var ok bool
		var apt int
		var tid uint32
		if err := th.Run(func() { tid, apt, ok = th.OnThread() }); err != nil {
			t.Fatal(err)
		}
		if !ok || tid != th.TID() || (apt != AptSTA && apt != AptMainSTA) {
			t.Fatalf("run %d: tid %d (thread %d) apt %d ok %v", i, tid, th.TID(), apt, ok)
		}
	}
}

func TestOffThreadIsNotOK(t *testing.T) {
	th, err := New(ModeSTA)
	if err != nil {
		t.Fatal(err)
	}
	defer th.Stop()
	if _, _, ok := th.OnThread(); ok {
		t.Fatal("OnThread true from the test goroutine")
	}
}

func TestMTAModeIsFlagged(t *testing.T) {
	th, err := New(ModeMTA)
	if err != nil {
		t.Fatal(err)
	}
	defer th.Stop()
	var ok bool
	var apt int
	_ = th.Run(func() { _, apt, ok = th.OnThread() })
	if ok || apt != AptMTA {
		t.Fatalf("MTA thread: apt %d ok %v", apt, ok)
	}
}

func TestStopRejectsWork(t *testing.T) {
	th, err := New(ModeSTA)
	if err != nil {
		t.Fatal(err)
	}
	th.Stop()
	<-th.Done()
	if th.Submit(func() {}) {
		t.Fatal("Submit after Stop")
	}
	if err := th.Run(func() {}); err != ErrStopped {
		t.Fatalf("Run after Stop: %v", err)
	}
	th.Stop() // idempotent
}

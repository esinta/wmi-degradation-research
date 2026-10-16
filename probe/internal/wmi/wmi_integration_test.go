//go:build wmiintegration

// Real-WMI tests. They make WMI calls, so they run only on a probe host
// (build: go test -c -tags wmiintegration ./internal/wmi), never on the dev
// laptop while it soaks.
package wmi

import (
	"context"
	"testing"
	"time"

	"wmiresearch/probe/internal/hresult"
)

func dial(t *testing.T, opts Options) *Conn {
	t.Helper()
	if opts.Namespace == "" {
		opts.Namespace = `root\cimv2`
	}
	c, ci, err := Dial(opts)
	if err != nil {
		t.Fatalf("dial %s: %v (%+v)", opts.Namespace, err, ci.Err)
	}
	return c
}

func released(t *testing.T, c *Conn) (outstanding, double int) {
	t.Helper()
	done := make(chan [2]int, 1)
	c.OnReleased = func(o, d int) { done <- [2]int{o, d} }
	c.Close()
	select {
	case r := <-done:
		return r[0], r[1]
	case <-time.After(30 * time.Second):
		t.Fatal("release did not run")
	}
	return
}

// The correct client: on its STA thread, every reference released, arrays
// read and cleared.
func TestCorrectClientIsClean(t *testing.T) {
	c := dial(t, Options{})
	r := c.Query(context.Background(), "SELECT Caption, Version, MUILanguages FROM Win32_OperatingSystem", time.Minute, false, nil)
	if r.Status != StatusOK || r.RowsN != 1 || len(r.Rows) != 1 {
		t.Fatalf("status %s rows %d err %+v", r.Status, r.RowsN, r.Err)
	}
	if !r.AptOK || r.TID != c.TID() {
		t.Fatalf("apartment: tid %d (conn %d) apt %d", r.TID, c.TID(), r.AptType)
	}
	if r.ArrayProps != 1 || r.ArrayN == 0 {
		t.Fatalf("MUILanguages array not read: %d props %d elems", r.ArrayProps, r.ArrayN)
	}
	if r.LedgerOutstanding != 0 || r.LedgerDouble != 0 || r.LedgerLeaked != 0 || r.LedgerAcquired == 0 {
		t.Fatalf("ledger: acquired %d outstanding %d double %d leaked %d", r.LedgerAcquired, r.LedgerOutstanding, r.LedgerDouble, r.LedgerLeaked)
	}
	if r.EnumEndHR != hresult.SFalse {
		t.Fatalf("enumeration ended with %s", hresult.Name(r.EnumEndHR))
	}
	if o, d := released(t, c); o != 0 || d != 0 {
		t.Fatalf("connection ledger: outstanding %d double %d", o, d)
	}
}

// The buggy arms must actually be buggy.
func TestLeakArraysLeaves(t *testing.T) {
	c := dial(t, Options{LeakArrays: true})
	defer c.Close()
	r := c.Query(context.Background(), "SELECT MUILanguages FROM Win32_OperatingSystem", time.Minute, false, nil)
	if r.LedgerLeaked != 1 || r.LedgerOutstanding != 1 {
		t.Fatalf("leak arm: leaked %d outstanding %d", r.LedgerLeaked, r.LedgerOutstanding)
	}
}

func TestCrossApartmentIsFlagged(t *testing.T) {
	c := dial(t, Options{CrossApartment: true})
	defer c.Close()
	r := c.Query(context.Background(), "SELECT Caption FROM Win32_OperatingSystem", time.Minute, false, nil)
	if r.Status != StatusOK || r.AptOK {
		t.Fatalf("status %s apt_ok %v apt %d", r.Status, r.AptOK, r.AptType)
	}
}

// H-enum (design §2.2): where does an invalid class fail, and what does
// oleutil.ForEach report? Logged, not asserted: this is the measurement.
func TestHEnum(t *testing.T) {
	c := dial(t, Options{})
	defer c.Close()
	const q = "SELECT * FROM Win32_NoSuchClass_Probe2"
	r := c.Query(context.Background(), q, time.Minute, false, nil)
	t.Logf("strict: status %s err %+v enum_ran %v end %s", r.Status, r.Err, r.EnumRan, hresult.Name(r.EnumEndHR))
	fe := c.QueryForEach(q)
	t.Logf("ForEach: exec err %+v foreach err %+v items %d", fe.ExecErr, fe.ForEachErr, fe.Items)
	if r.Status == StatusOK {
		t.Fatal("invalid class succeeded under the strict loop")
	}
}

func TestErrorCodesIncludeSCode(t *testing.T) {
	_, ci, err := Dial(Options{Namespace: `root\NoSuchNamespace_Probe2`})
	if err == nil {
		t.Fatal("bad namespace connected")
	}
	if ci.Err == nil || hresult.Effective(ci.Err.HR, ci.Err.SCode) != hresult.WBEMEInvalidNamespace {
		t.Fatalf("connect error %+v", ci.Err)
	}
}

func TestAbandonAndLateResult(t *testing.T) {
	c := dial(t, Options{})
	late := make(chan Result, 1)
	// A deadline far below any real query's latency.
	r := c.Query(context.Background(), "SELECT Name FROM Win32_Process", time.Microsecond, true, func(l Result) { late <- l })
	if r.Status != StatusAbandoned {
		t.Skipf("query beat a 1 µs deadline (%s)", r.Status)
	}
	select {
	case l := <-late:
		if l.Status != StatusAbandoned || l.RowsN == 0 || l.LedgerOutstanding != 0 {
			t.Fatalf("late result %+v", l)
		}
	case <-time.After(time.Minute):
		t.Fatal("late result never came")
	}
	if o, d := released(t, c); o != 0 || d != 0 {
		t.Fatalf("connection ledger: outstanding %d double %d", o, d)
	}
}

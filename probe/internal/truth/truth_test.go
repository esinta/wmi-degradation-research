package truth

import (
	"errors"
	"testing"
	"time"

	"wmiresearch/probe/internal/catalog"
	"wmiresearch/probe/internal/sysinfo"
	"wmiresearch/probe/internal/wmi"
)

type fake struct {
	snaps    []sysinfo.Snapshot
	creates  []map[uint32]int64
	names    []map[string]bool
	registry int
}

func (f *fake) Snapshot() (sysinfo.Snapshot, error) {
	if len(f.snaps) == 0 {
		return nil, errors.New("no snapshot")
	}
	s := f.snaps[0]
	f.snaps = f.snaps[1:]
	return s, nil
}

func (f *fake) CreateTime(pid uint32) (int64, bool) {
	m := f.creates[0]
	if len(f.creates) > 1 {
		f.creates = f.creates[1:]
	}
	c, ok := m[pid]
	return c, ok
}

func (f *fake) ServiceNames(bool) (map[string]bool, error) {
	n := f.names[0]
	f.names = f.names[1:]
	return n, nil
}

func (f *fake) RegistryCount(string) (int, error) { return f.registry, nil }

func query(key string) catalog.Query {
	for _, q := range catalog.Production() {
		if q.Key == key {
			return q
		}
	}
	panic(key)
}

func ok(rows ...wmi.Row) wmi.Result {
	return wmi.Result{Status: wmi.StatusOK, Rows: rows, RowsN: len(rows), EnumEndHR: 1}
}

// A FILETIME and its CIM datetime in a +060 zone.
const (
	ftA  = int64(134000000000000000)
	cimA = "20250803125320.000000+060"
)

func TestCIMDatetime(t *testing.T) {
	ft, ok := cimToFiletime(cimA)
	if !ok {
		t.Fatal("parse failed")
	}
	want := time.Date(2025, 8, 3, 11, 53, 20, 0, time.UTC)
	if got := FiletimeToTime(ft); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if _, ok := cimToFiletime("garbage"); ok {
		t.Fatal("garbage parsed")
	}
}

func TestPIDAliveButEmptyIsS1(t *testing.T) {
	f := &fake{creates: []map[uint32]int64{{100: ftA}}}
	c := NewChecker(f)
	q := query("proc_pid")
	pre := c.Before(q, 100)
	o := c.After(q, pre, ok())
	if o.Kind != "pid-alive" || o.Mask&S1 == 0 || o.Missing != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestPIDAliveMatches(t *testing.T) {
	cim := FiletimeToTime(ftA).Format("20060102150405.000000") + "+000"
	f := &fake{creates: []map[uint32]int64{{100: ftA}}}
	c := NewChecker(f)
	q := query("proc_pid")
	o := c.After(q, c.Before(q, 100), ok(wmi.Row{"ProcessId": int32(100), "CreationDate": cim}))
	if o.Mask != 0 || o.Mismatch != 0 {
		t.Fatalf("%+v", o)
	}
}

func TestPIDGoneButReturnedIsPhantom(t *testing.T) {
	f := &fake{creates: []map[uint32]int64{{}}}
	c := NewChecker(f)
	q := query("proc_pid")
	o := c.After(q, c.Before(q, 100), ok(wmi.Row{"ProcessId": int32(100)}))
	if o.Kind != "pid-gone" || o.Mask&S5 == 0 {
		t.Fatalf("%+v", o)
	}
}

func TestPIDRaceHasNoTruth(t *testing.T) {
	f := &fake{creates: []map[uint32]int64{{100: ftA}, {}}}
	c := NewChecker(f)
	q := query("proc_pid")
	o := c.After(q, c.Before(q, 100), ok())
	if o.Kind != "pid-race" || o.Mask != 0 {
		t.Fatalf("%+v", o)
	}
}

func TestProcSetBracketing(t *testing.T) {
	before := sysinfo.Snapshot{1: {PID: 1, Create: 10}, 2: {PID: 2, Create: 20}, 3: {PID: 3, Create: 30}}
	after := sysinfo.Snapshot{1: {PID: 1, Create: 10}, 2: {PID: 2, Create: 20}, 4: {PID: 4, Create: 40}}
	q := query("proc_all")

	// 3 exited and 4 started during the query: both optional. 2 missing: S2.
	c := NewChecker(&fake{snaps: []sysinfo.Snapshot{before, after}})
	o := c.After(q, c.Before(q, 0), ok(wmi.Row{"ProcessId": int32(1)}, wmi.Row{"ProcessId": int32(4)}))
	if o.Missing != 1 || o.Phantom != 0 || o.Mask != S2 || o.Lo != 2 || o.Hi != 4 {
		t.Fatalf("%+v", o)
	}

	// 9 was never there: phantom, S5.
	c = NewChecker(&fake{snaps: []sysinfo.Snapshot{before, after}})
	o = c.After(q, c.Before(q, 0), ok(wmi.Row{"ProcessId": int32(1)}, wmi.Row{"ProcessId": int32(2)}, wmi.Row{"ProcessId": int32(9)}))
	if o.Missing != 0 || o.Phantom != 1 || o.Mask != S5 {
		t.Fatalf("%+v", o)
	}

	// Empty result: S1 (also impossible-empty).
	c = NewChecker(&fake{snaps: []sysinfo.Snapshot{before, after}})
	r := ok()
	o = c.After(q, c.Before(q, 0), r)
	if o.Mask&S1 == 0 {
		t.Fatalf("%+v", o)
	}
}

func TestServiceNames(t *testing.T) {
	b := map[string]bool{"a": true, "b": true}
	a := map[string]bool{"a": true, "b": true, "c": true}
	c := NewChecker(&fake{names: []map[string]bool{b, a}})
	q := query("svc")
	o := c.After(q, c.Before(q, 0), ok(wmi.Row{"Name": "A"}, wmi.Row{"Name": "C"}))
	if o.Missing != 1 || o.MissingKeys[0] != "b" || o.Mask != S2 {
		t.Fatalf("%+v", o)
	}
}

func TestInvariantTransientAndRebaseline(t *testing.T) {
	f := &fake{registry: 7}
	c := NewChecker(f)
	var events []string
	c.OnRebaseline = func(k, d string) { events = append(events, k+": "+d) }
	q := query("fw_rules")
	r := func(ids ...string) wmi.Result {
		var rows []wmi.Row
		for _, id := range ids {
			rows = append(rows, wmi.Row{"InstanceID": id})
		}
		return ok(rows...)
	}
	if o := c.After(q, Pre{}, r("x", "y")); o.Kind != "t0" {
		t.Fatalf("t0: %+v", o)
	}
	// Transient loss: flagged S2, baseline unchanged.
	if o := c.After(q, Pre{}, r("x")); o.Mask != S2 || o.RegistryCount != 7 {
		t.Fatalf("transient: %+v", o)
	}
	if o := c.After(q, Pre{}, r("x", "y")); o.Mask != 0 {
		t.Fatalf("back to t0: %+v", o)
	}
	// A real change repeats: rebaseline on the third identical answer.
	for i := range RebaselineAfter {
		o := c.After(q, Pre{}, r("x", "y", "z"))
		if o.Mask != S5 {
			t.Fatalf("change %d: %+v", i, o)
		}
		if (i == RebaselineAfter-1) != o.Rebaselined {
			t.Fatalf("rebaseline at %d: %+v", i, o)
		}
	}
	if o := c.After(q, Pre{}, r("x", "y", "z")); o.Mask != 0 {
		t.Fatalf("after rebaseline: %+v", o)
	}
	if len(events) != 1 {
		t.Fatalf("events %v", events)
	}
}

func TestExactlyOneAndErrors(t *testing.T) {
	c := NewChecker(&fake{})
	q := query("def_status")
	if o := c.After(q, Pre{}, ok()); o.Mask&S1 == 0 {
		t.Fatalf("%+v", o)
	}
	if o := c.After(q, Pre{}, ok(wmi.Row{}, wmi.Row{})); o.Mask != S5 {
		t.Fatalf("%+v", o)
	}
	if o := c.After(q, Pre{}, wmi.Result{Status: wmi.StatusError}); o.Kind != "skipped" || o.Mask != 0 {
		t.Fatalf("%+v", o)
	}
}

func TestMaskFromResult(t *testing.T) {
	res := ok()
	res.EnumEndHR = 0x80041010
	res.PropsFailed = 1
	if m := Mask(res, Outcome{}); m != S3|S4 {
		t.Fatalf("mask %b", m)
	}
}

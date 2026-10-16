// Package truth checks WMI results against non-WMI sources and classifies
// silent failures (design §6.6):
//
//	S1 impossible-empty   0 rows where truth or an invariant needs >= 1
//	S2 truncated          a key that truth says must be there is missing
//	S3 error-ended enum   the enumeration ended with a failure HRESULT
//	                      (oleutil.ForEach would have reported success)
//	S4 partial objects    objects or properties skipped on error
//	S5 content mismatch   phantom keys, or a key property that differs
//
// Bracketing: truth is read immediately before and after the query. A key in
// both snapshots must be in the result; a key in neither must not be.
// Invariants: for classes static on an isolated VM, the expected answer is the
// first successful answer of the run (t0). A changed answer that repeats
// identically RebaselineAfter times is taken as a real change: the baseline
// moves and an event is logged, so analysis can drop the rows before it.
package truth

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wmiresearch/probe/internal/catalog"
	"wmiresearch/probe/internal/sysinfo"
	"wmiresearch/probe/internal/wmi"
)

// Silent-failure bits.
const (
	S1 = 1 << iota
	S2
	S3
	S4
	S5
)

// RebaselineAfter is how many identical changed answers move an invariant.
const RebaselineAfter = 3

// CreateTolerance is the allowed difference between WMI's CreationDate
// (microseconds) and the native create time (100 ns).
const CreateTolerance = time.Millisecond

// Sources are the non-WMI truth sources (replaced by fakes in tests).
type Sources interface {
	Snapshot() (sysinfo.Snapshot, error)
	CreateTime(pid uint32) (int64, bool)
	ServiceNames(drivers bool) (map[string]bool, error)
	RegistryCount(which string) (int, error)
}

// Pre is the state read before a query.
type Pre struct {
	pid      uint32
	pidOK    bool
	pidCreat int64
	snap     sysinfo.Snapshot
	names    map[string]bool
	err      error
}

// Outcome is the truth result for one query.
type Outcome struct {
	Kind             string
	Lo, Hi           int // expected row-count bounds (-1 = unknown)
	Missing, Phantom int
	Mismatch         int
	MissingKeys      []string
	PhantomKeys      []string
	Mask             int // S1 | S2 | S5 from truth
	Note             string
	Rebaselined      bool
	RegistryCount    int // registry cross-check at a mismatch (-1 = not read)
}

type invariant struct {
	set      map[string]bool
	count    int
	pending  string // fingerprint of a changed answer
	repeats  int
	registry int
	haveBase bool
}

// Checker holds the invariants of one run. Safe for concurrent use.
type Checker struct {
	src Sources
	mu  sync.Mutex
	inv map[string]*invariant
	// OnRebaseline is called when an invariant moves.
	OnRebaseline func(key, detail string)
}

// NewChecker returns a checker reading from src.
func NewChecker(src Sources) *Checker {
	return &Checker{src: src, inv: map[string]*invariant{}}
}

// Before reads the pre-query truth. pid is the proc_pid target (else 0).
func (c *Checker) Before(q catalog.Query, pid uint32) Pre {
	p := Pre{pid: pid}
	switch q.Truth {
	case catalog.TruthPID:
		p.pidCreat, p.pidOK = c.src.CreateTime(pid)
	case catalog.TruthProcSet:
		p.snap, p.err = c.src.Snapshot()
	case catalog.TruthServices, catalog.TruthDrivers:
		p.names, p.err = c.src.ServiceNames(q.Truth == catalog.TruthDrivers)
	}
	return p
}

// After reads the post-query truth and compares. Only results with status
// ok are compared; errors are errors, not silent failures.
func (c *Checker) After(q catalog.Query, pre Pre, res wmi.Result) Outcome {
	o := Outcome{Kind: q.Truth.String(), Lo: -1, Hi: -1, RegistryCount: -1}
	if res.Status != wmi.StatusOK {
		o.Kind = "skipped"
		return o
	}
	switch q.Truth {
	case catalog.TruthPID:
		c.pid(q, pre, res, &o)
	case catalog.TruthProcSet:
		post, err := c.src.Snapshot()
		if pre.err != nil || err != nil {
			o.Kind, o.Note = "error", fmt.Sprint(pre.err, err)
			break
		}
		procSet(q, pre.snap, post, res, &o)
	case catalog.TruthServices, catalog.TruthDrivers:
		post, err := c.src.ServiceNames(q.Truth == catalog.TruthDrivers)
		if pre.err != nil || err != nil {
			o.Kind, o.Note = "error", fmt.Sprint(pre.err, err)
			break
		}
		nameSet(q, pre.names, post, res, &o)
	case catalog.TruthKeySet, catalog.TruthCount:
		c.invariant(q, res, &o)
	case catalog.TruthExactlyOne:
		o.Lo, o.Hi = 1, 1
		switch {
		case len(res.Rows) == 0:
			o.Missing, o.Mask = 1, S1
		case len(res.Rows) > 1:
			o.Phantom, o.Mask = len(res.Rows)-1, S5
		}
	}
	if q.ImpossibleEmpty && res.RowsN == 0 {
		o.Mask |= S1
	}
	return o
}

func (c *Checker) pid(q catalog.Query, pre Pre, res wmi.Result, o *Outcome) {
	postCreat, postOK := c.src.CreateTime(pre.pid)
	switch {
	case pre.pidOK && postOK && pre.pidCreat == postCreat:
		o.Kind, o.Lo, o.Hi = "pid-alive", 1, 1
		if len(res.Rows) == 0 {
			o.Missing, o.Mask = 1, S1
			o.MissingKeys = []string{strconv.FormatUint(uint64(pre.pid), 10)}
			return
		}
		if len(res.Rows) > 1 {
			o.Phantom, o.Mask = len(res.Rows)-1, S5
		}
		r := res.Rows[0]
		if id, ok := toUint(r[q.KeyProp]); !ok || id != uint64(pre.pid) {
			o.Mismatch++
			o.Mask |= S5
			return
		}
		if ft, ok := cimToFiletime(r["CreationDate"]); ok && absDur(ft-pre.pidCreat) > int64(CreateTolerance/100) {
			o.Mismatch++
			o.Mask |= S5
			o.Note = "CreationDate differs from native create time"
		}
	case !pre.pidOK && !postOK:
		o.Kind, o.Lo, o.Hi = "pid-gone", 0, 0
		if len(res.Rows) > 0 {
			o.Phantom, o.Mask = len(res.Rows), S5
			o.PhantomKeys = []string{strconv.FormatUint(uint64(pre.pid), 10)}
		}
	default:
		o.Kind = "pid-race" // started or exited during the query: no truth
	}
}

func procSet(q catalog.Query, before, after sysinfo.Snapshot, res wmi.Result, o *Outcome) {
	must := map[uint64]int64{}
	for pid, p := range before {
		if a, ok := after[pid]; ok && a.Create == p.Create {
			must[uint64(pid)] = p.Create
		}
	}
	allowed := map[uint64]bool{}
	for pid := range before {
		allowed[uint64(pid)] = true
	}
	for pid := range after {
		allowed[uint64(pid)] = true
	}
	got := map[uint64]bool{}
	for _, r := range res.Rows {
		id, ok := toUint(r[q.KeyProp])
		if !ok {
			o.Mismatch++
			continue
		}
		got[id] = true
		if !allowed[id] {
			o.Phantom++
			o.PhantomKeys = appendKey(o.PhantomKeys, strconv.FormatUint(id, 10))
		} else if create, ok := must[id]; ok {
			if ft, ok := cimToFiletime(r["CreationDate"]); ok && absDur(ft-create) > int64(CreateTolerance/100) {
				o.Mismatch++ // PID reused with a different process
			}
		}
	}
	for id := range must {
		if !got[id] {
			o.Missing++
			o.MissingKeys = appendKey(o.MissingKeys, strconv.FormatUint(id, 10))
		}
	}
	o.Lo, o.Hi = len(must), len(allowed)
	setMask(o, len(res.Rows))
}

func nameSet(q catalog.Query, before, after map[string]bool, res wmi.Result, o *Outcome) {
	allowed := map[string]bool{}
	must := map[string]bool{}
	for n := range before {
		allowed[n] = true
		if after[n] {
			must[n] = true
		}
	}
	for n := range after {
		allowed[n] = true
	}
	got := map[string]bool{}
	for _, r := range res.Rows {
		n := strings.ToLower(fmt.Sprint(r[q.KeyProp]))
		got[n] = true
		if !allowed[n] {
			o.Phantom++
			o.PhantomKeys = appendKey(o.PhantomKeys, n)
		}
	}
	for n := range must {
		if !got[n] {
			o.Missing++
			o.MissingKeys = appendKey(o.MissingKeys, n)
		}
	}
	o.Lo, o.Hi = len(must), len(allowed)
	setMask(o, len(res.Rows))
}

func setMask(o *Outcome, rows int) {
	if o.Missing > 0 {
		if rows == 0 {
			o.Mask |= S1
		} else {
			o.Mask |= S2
		}
	}
	if o.Phantom > 0 || o.Mismatch > 0 {
		o.Mask |= S5
	}
}

func (c *Checker) invariant(q catalog.Query, res wmi.Result, o *Outcome) {
	cur := map[string]bool{}
	if q.Truth == catalog.TruthKeySet {
		for _, r := range res.Rows {
			cur[strings.ToLower(fmt.Sprint(r[q.KeyProp]))] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	inv := c.inv[q.Key]
	if inv == nil {
		inv = &invariant{}
		c.inv[q.Key] = inv
	}
	if !inv.haveBase {
		inv.set, inv.count, inv.haveBase = cur, len(res.Rows), true
		inv.registry = c.registry(q)
		o.Kind, o.Lo, o.Hi, o.Note = "t0", len(res.Rows), len(res.Rows), "baseline"
		return
	}
	o.Lo, o.Hi = inv.count, inv.count
	if q.Truth == catalog.TruthKeySet {
		for k := range inv.set {
			if !cur[k] {
				o.Missing++
				o.MissingKeys = appendKey(o.MissingKeys, k)
			}
		}
		for k := range cur {
			if !inv.set[k] {
				o.Phantom++
				o.PhantomKeys = appendKey(o.PhantomKeys, k)
			}
		}
	} else if d := len(res.Rows) - inv.count; d < 0 {
		o.Missing = -d
	} else {
		o.Phantom = d
	}
	if o.Missing == 0 && o.Phantom == 0 {
		inv.pending, inv.repeats = "", 0
		return
	}
	setMask(o, len(res.Rows))
	o.RegistryCount = c.registry(q)
	fp := fingerprint(cur, len(res.Rows))
	if fp == inv.pending {
		inv.repeats++
	} else {
		inv.pending, inv.repeats = fp, 1
	}
	if inv.repeats >= RebaselineAfter {
		detail := fmt.Sprintf("count %d -> %d, registry %d -> %d", inv.count, len(res.Rows), inv.registry, o.RegistryCount)
		inv.set, inv.count, inv.registry = cur, len(res.Rows), o.RegistryCount
		inv.pending, inv.repeats = "", 0
		o.Rebaselined = true
		if c.OnRebaseline != nil {
			c.OnRebaseline(q.Key, detail)
		}
	}
}

func (c *Checker) registry(q catalog.Query) int {
	if q.Registry == "" {
		return -1
	}
	n, err := c.src.RegistryCount(q.Registry)
	if err != nil {
		return -1
	}
	return n
}

func fingerprint(set map[string]bool, n int) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strconv.Itoa(n) + "|" + strings.Join(keys, "\x00")
}

// maxKeys bounds the keys kept per outcome for truth.csv.
const maxKeys = 20

func appendKey(ks []string, k string) []string {
	if len(ks) < maxKeys {
		return append(ks, k)
	}
	return ks
}

// Mask combines the truth bits with the bits that come from the result
// itself (S3, S4).
func Mask(res wmi.Result, o Outcome) int {
	m := o.Mask
	if res.EnumEndHR&0x80000000 != 0 {
		m |= S3
	}
	if res.ItemsSkipped > 0 || res.PropsFailed > 0 {
		m |= S4
	}
	return m
}

func toUint(v any) (uint64, bool) {
	switch x := v.(type) {
	case int32:
		return uint64(uint32(x)), true
	case uint32:
		return uint64(x), true
	case int64:
		return uint64(x), x >= 0
	case uint64:
		return x, true
	case int:
		return uint64(x), x >= 0
	case int16:
		return uint64(uint16(x)), true
	case uint16:
		return uint64(x), true
	case string:
		n, err := strconv.ParseUint(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func absDur(d int64) int64 {
	if d < 0 {
		return -d
	}
	return d
}

// filetimeEpoch is 1601-01-01 to 1970-01-01 in 100 ns units.
const filetimeEpoch = 116444736000000000

// cimToFiletime parses a CIM datetime (yyyymmddHHMMSS.mmmmmmsUUU, UUU =
// UTC offset in minutes) into a FILETIME.
func cimToFiletime(v any) (int64, bool) {
	s, ok := v.(string)
	if !ok || len(s) < 25 {
		return 0, false
	}
	t, err := time.Parse("20060102150405.000000", s[:21])
	if err != nil {
		return 0, false
	}
	off, err := strconv.Atoi(s[22:25])
	if err != nil {
		return 0, false
	}
	if s[21] == '-' {
		off = -off
	} else if s[21] != '+' {
		return 0, false
	}
	t = t.Add(-time.Duration(off) * time.Minute)
	return t.UnixNano()/100 + filetimeEpoch, true
}

// FiletimeToTime converts a FILETIME to time.Time (UTC).
func FiletimeToTime(ft int64) time.Time {
	return time.Unix(0, (ft-filetimeEpoch)*100).UTC()
}

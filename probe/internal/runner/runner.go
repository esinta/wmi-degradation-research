// Package runner executes one arm (design §3.3, §4): the fixed-rate schedule
// feeds per-namespace workers, each worker owns one connection slot, the
// strategy decides replacements, every query is checked against truth and
// written as one row, and a 10 s sampler writes resources, checks the abort
// thresholds and watches for hung calls.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wmiresearch/probe/internal/abort"
	"wmiresearch/probe/internal/catalog"
	"wmiresearch/probe/internal/etw"
	"wmiresearch/probe/internal/out"
	"wmiresearch/probe/internal/sampler"
	"wmiresearch/probe/internal/sched"
	"wmiresearch/probe/internal/strategy"
	"wmiresearch/probe/internal/sysinfo"
	"wmiresearch/probe/internal/truth"
	"wmiresearch/probe/internal/wmi"
)

// Config is one arm.
type Config struct {
	Arm         string
	Host        string
	OutRoot     string
	RunID       string
	ClientClass string // "correct" | "buggy"
	Bug         string // buggy only: "array-leak" | "cross-apartment"

	Mix        string
	Queries    []catalog.Query
	K          float64
	Duration   time.Duration
	Seed       int64
	Strategy   strategy.Config
	Deadline   time.Duration
	Cimv2Conns int

	SampleInterval time.Duration
	HangWarn       time.Duration
	HangAbort      time.Duration
	ReleaseTest    time.Duration // after the arm: close everything, keep sampling this long (ST-3)
	Truth          bool
	Attribution    map[string]string // class -> provider DLL (from pre-flight)
	Limits         abort.Limits

	Commit   string
	Priority string // process priority class as started (and "->normal" if raised)
	Args     []string
}

// Conn is what the runner needs from a connection (wmi.Conn; fakes in tests).
type Conn interface {
	ID() string
	CreatedAt() time.Time
	Queries() uint64
	Objects() uint64
	RunningSince() time.Time
	Query(ctx context.Context, wql string, deadline time.Duration, abandon bool, late func(wmi.Result)) wmi.Result
	Close()
}

// Env holds the runner's dependencies.
type Env struct {
	Dial    func(opts wmi.Options, onReleased func(outstanding, double int)) (Conn, wmi.ConnectInfo, error)
	Truth   truth.Sources
	Sampler interface{ Sample() sampler.Sample }
	OSInfo  sysinfo.OSInfo
	// Meter is the ETW foreign-WMI meter (nil = none); MeterDesc goes to
	// meta.json ("on 1m0s every 15m0s", or why it is unavailable).
	Meter     interface{ Drain() etw.Drained }
	MeterDesc string
}

// NativeEnv is the production environment.
func NativeEnv(diskPath string, attribution map[string]string) Env {
	return Env{
		Dial: func(opts wmi.Options, onReleased func(int, int)) (Conn, wmi.ConnectInfo, error) {
			c, ci, err := wmi.Dial(opts)
			if err != nil {
				return nil, ci, err
			}
			c.OnReleased = onReleased
			return c, ci, nil
		},
		Truth:   truth.Native{},
		Sampler: sampler.New(diskPath, attribution),
		OSInfo:  sysinfo.GetOSInfo(runtime.NumCPU()),
	}
}

// Meta is meta.json (design §6.1).
type Meta struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Arm           string            `json:"arm"`
	Host          string            `json:"host"`
	ClientClass   string            `json:"client_class"`
	Bug           string            `json:"bug,omitempty"`
	ProbeCommit   string            `json:"probe_commit"`
	ETW           string            `json:"etw_meter"`
	Priority      string            `json:"priority_class"`
	GoVersion     string            `json:"go_version"`
	Args          []string          `json:"args"`
	Mix           string            `json:"mix"`
	K             float64           `json:"k"`
	PerHourAtK    float64           `json:"queries_per_hour_at_k"`
	CatalogHash   string            `json:"catalog_hash"`
	Catalog       []catalog.Query   `json:"catalog"`
	Strategy      string            `json:"strategy"`
	TimedInterval string            `json:"timed_interval,omitempty"`
	Abandons      bool              `json:"abandons_at_deadline"`
	DeadlineMS    int64             `json:"deadline_ms"`
	Cimv2Conns    int               `json:"cimv2_conns"`
	Slots         []string          `json:"slots"`
	Seed          int64             `json:"seed"`
	Duration      string            `json:"duration"`
	ReleaseTest   string            `json:"release_test,omitempty"`
	Truth         bool              `json:"truth"`
	Attribution   map[string]string `json:"attribution,omitempty"`
	Limits        abort.Limits      `json:"abort_limits"`
	OS            sysinfo.OSInfo    `json:"os"`
	StartUTC      time.Time         `json:"start_utc"`
	EndUTC        *time.Time        `json:"end_utc,omitempty"`
	EndReason     string            `json:"end_reason,omitempty"`
	Totals        map[string]uint64 `json:"totals,omitempty"`
}

// Validate checks a config before anything starts.
func (c *Config) Validate() error {
	switch c.ClientClass {
	case "correct":
		if c.Bug != "" {
			return errors.New("a correct-client arm cannot enable a bug")
		}
		if strings.HasPrefix(c.Arm, "buggy-") {
			return errors.New(`arm names starting with "buggy-" are reserved for client class buggy`)
		}
	case "buggy":
		if !strings.HasPrefix(c.Arm, "buggy-") {
			return errors.New(`a buggy-client arm must be named "buggy-<arm>" so its results never mix with correct-client results`)
		}
		if c.Bug != "array-leak" && c.Bug != "cross-apartment" {
			return fmt.Errorf("buggy arm needs -bug array-leak | cross-apartment, got %q", c.Bug)
		}
	default:
		return fmt.Errorf("client class %q (correct | buggy)", c.ClientClass)
	}
	if c.Arm == "" || strings.ContainsAny(c.Arm, `\/:*?"<>|`) {
		return fmt.Errorf("bad arm name %q", c.Arm)
	}
	if c.K <= 0 || c.Duration <= 0 || c.Deadline <= 0 || c.Cimv2Conns < 1 || c.SampleInterval <= 0 {
		return errors.New("k, duration, deadline, cimv2 connections and sample interval must be positive")
	}
	if len(c.Queries) == 0 {
		return errors.New("empty catalog")
	}
	return nil
}

// Dir is the run's output directory.
func (c *Config) Dir() string { return filepath.Join(c.OutRoot, c.Host, c.Arm, c.RunID) }

type job struct {
	sched.Job
	slot *slot
}

type slot struct {
	name   string
	ns     string
	queue  chan job
	rng    *rand.Rand
	conn   Conn
	gen    int
	prevID string
	reason string // why the next connection is made
	// lastUsed: read by the sampler goroutine for hang checks via conn only.
	lastUsed   time.Time
	failStreak int
	nextDial   time.Time
	hungWarned atomic.Bool
	connMu     sync.Mutex // guards conn for the sampler's hang check
}

func (s *slot) current() Conn {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn
}

func (s *slot) set(c Conn) {
	s.connMu.Lock()
	s.conn = c
	s.connMu.Unlock()
}

type pidPool struct {
	alive []uint32
	gone  []uint32
}

// Runner is one arm in progress.
type Runner struct {
	cfg  Config
	env  Env
	ws   *out.Set
	meta Meta
	tc   *truth.Checker

	slots []*slot
	byNS  map[string][]*slot

	seq       atomic.Uint64
	pids      atomic.Pointer[pidPool]
	classHost atomic.Pointer[map[string]uint32]
	canaryUS  atomic.Int64

	hostQMu sync.Mutex
	hostQ   map[uint32]uint64

	// Counters.
	queries, okN, errN, abandonedN, overloadedN, noconnN atomic.Uint64
	silent                                               [5]atomic.Uint64
	connects, connectFails, recycles                     atomic.Uint64
	scheduled, dropped                                   atomic.Uint64
	hungNow                                              atomic.Int64
	wmiOpsSelf, wmiOpsForeign, wmiOpsInternal            uint64 // sampler goroutine only
	recMu                                                sync.Mutex
	recByReason                                          map[string]uint64

	// Abandoned calls whose row is written when the call returns.
	lateMu      sync.Mutex
	lateClosed  bool
	latePending map[uint64]lateRow

	abortOnce   sync.Once
	abortReason atomic.Value // string
	cancelRun   context.CancelFunc

	errOnce  sync.Once
	writeErr error

	// Connection releases run on each connection's own thread and report
	// after Close returns; shutdown waits for them before closing the files.
	relWG     sync.WaitGroup
	relMu     sync.RWMutex
	relClosed bool

	// CPU means over the arm, from the sampler goroutine only.
	cpuHost, cpuInduced float64
	cpuN                int
}

type lateRow struct {
	base []string
	pid  uint32
}

// Summary is what Run reports.
type Summary struct {
	EndReason      string
	Dir            string
	Totals         map[string]uint64
	MeanHostCPU    float64 // over the arm (not the release test)
	MeanInducedCPU float64
	Samples        int
}

// Run executes the arm.
func Run(ctx context.Context, cfg Config, env Env) (Summary, error) {
	if err := cfg.Validate(); err != nil {
		return Summary{}, err
	}
	dir := cfg.Dir()
	if _, err := os.Stat(dir); err == nil {
		return Summary{}, fmt.Errorf("%s exists: one directory per run", dir)
	}
	ws, err := out.NewSet(dir, out.Schemas())
	if err != nil {
		return Summary{}, err
	}
	r := &Runner{cfg: cfg, env: env, ws: ws, hostQ: map[uint32]uint64{}, recByReason: map[string]uint64{}, latePending: map[uint64]lateRow{}}
	r.tc = truth.NewChecker(env.Truth)
	r.tc.OnRebaseline = func(key, detail string) { r.event("invariant_rebaseline", "", "", 0, key+": "+detail) }
	r.pids.Store(&pidPool{})
	empty := map[string]uint32{}
	r.classHost.Store(&empty)
	r.buildSlots()

	r.meta = Meta{
		SchemaVersion: out.SchemaVersion, RunID: cfg.RunID, Arm: cfg.Arm, Host: cfg.Host, ClientClass: cfg.ClientClass, Bug: cfg.Bug,
		ProbeCommit: cfg.Commit, ETW: env.MeterDesc, Priority: cfg.Priority, GoVersion: runtime.Version(), Args: cfg.Args, Mix: cfg.Mix, K: cfg.K,
		PerHourAtK: cfg.K * catalog.PerHourTotal(cfg.Queries), CatalogHash: catalog.Hash(cfg.Queries), Catalog: cfg.Queries,
		Strategy: string(cfg.Strategy.Kind), Abandons: cfg.Strategy.Abandons(), DeadlineMS: cfg.Deadline.Milliseconds(),
		Cimv2Conns: cfg.Cimv2Conns, Seed: cfg.Seed, Duration: cfg.Duration.String(), Truth: cfg.Truth,
		Attribution: cfg.Attribution, Limits: cfg.Limits, OS: env.OSInfo, StartUTC: time.Now().UTC(),
	}
	if cfg.Strategy.Kind == strategy.Timed {
		r.meta.TimedInterval = cfg.Strategy.TimedInterval.String()
	}
	if cfg.ReleaseTest > 0 {
		r.meta.ReleaseTest = cfg.ReleaseTest.String()
	}
	for _, s := range r.slots {
		r.meta.Slots = append(r.meta.Slots, s.name)
	}
	if err := r.writeMeta(); err != nil {
		ws.Close()
		return Summary{}, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	r.cancelRun = cancel
	defer cancel()
	sampCtx, stopSamp := context.WithCancel(context.Background())
	sampDone := make(chan struct{})
	r.sampleOnce() // first sample: PID pool and attribution before the first query
	go func() {
		defer close(sampDone)
		r.sampleLoop(sampCtx, runCtx)
	}()

	var wg sync.WaitGroup
	for _, s := range r.slots {
		wg.Add(1)
		go func(s *slot) {
			defer wg.Done()
			r.worker(runCtx, s)
		}(s)
	}
	r.event("arm_start", "", "", 0, fmt.Sprintf("k=%g strategy=%s slots=%d", cfg.K, cfg.Strategy.Kind, len(r.slots)))

	timer := time.NewTimer(cfg.Duration)
	dispDone := make(chan struct{})
	go func() {
		defer close(dispDone)
		r.dispatch(runCtx)
	}()
	endReason := "duration"
	select {
	case <-timer.C:
	case <-runCtx.Done():
		if a, _ := r.abortReason.Load().(string); a != "" {
			endReason = "abort: " + a
		} else {
			endReason = "interrupted"
		}
	}
	timer.Stop()
	cancel()
	<-dispDone
	for _, s := range r.slots {
		close(s.queue)
	}
	waitTimeout(&wg, 2*time.Minute)

	for _, s := range r.slots {
		if c := s.current(); c != nil {
			r.retire(s, "shutdown")
		}
	}
	if !waitTimeout(&r.relWG, releaseWait) {
		r.event("release_wait_timeout", "", "", 0, releaseWait.String())
	}
	r.event("arm_end", "", "", 0, endReason)

	if cfg.ReleaseTest > 0 {
		debug.FreeOSMemory()
		r.event("release_test_start", "", "", 0, cfg.ReleaseTest.String())
		select {
		case <-time.After(cfg.ReleaseTest):
		case <-ctx.Done():
		}
		debug.FreeOSMemory()
		r.sampleOnce()
		r.event("release_test_end", "", "", 0, "")
	}
	stopSamp()
	<-sampDone
	r.flushLate()

	end := time.Now().UTC()
	r.meta.EndUTC, r.meta.EndReason = &end, endReason
	r.relMu.Lock()
	r.relClosed = true
	r.relMu.Unlock()
	r.meta.Totals = r.totals()
	merr := r.writeMeta()
	werr := ws.Close()
	sum := Summary{EndReason: endReason, Dir: dir, Totals: r.meta.Totals, Samples: r.cpuN}
	if r.cpuN > 0 {
		sum.MeanHostCPU, sum.MeanInducedCPU = r.cpuHost/float64(r.cpuN), r.cpuInduced/float64(r.cpuN)
	}
	return sum, errors.Join(r.writeErr, merr, werr)
}

// releaseWait bounds the shutdown wait for connection releases (a release
// waits for the connection's abandoned calls).
const releaseWait = time.Minute

func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func (r *Runner) buildSlots() {
	r.byNS = map[string][]*slot{}
	for i, ns := range catalog.Namespaces(r.cfg.Queries) {
		n := 1
		if strings.EqualFold(ns, catalog.NSCimv2) {
			n = r.cfg.Cimv2Conns
		}
		short := ns[strings.LastIndex(ns, `\`)+1:]
		for j := range n {
			s := &slot{
				name: fmt.Sprintf("%s#%d", short, j+1), ns: ns, queue: make(chan job, 1024),
				rng: rand.New(rand.NewSource(r.cfg.Seed + int64(i*100+j))), reason: "initial",
			}
			r.slots = append(r.slots, s)
			r.byNS[ns] = append(r.byNS[ns], s)
		}
	}
}

// dispatch feeds the schedule to the slots. A full slot queue drops the job
// and counts it; more than 1 % dropped aborts the arm (the rate is not
// sustainable, design §3.2).
func (r *Runner) dispatch(ctx context.Context) {
	s := sched.New(r.cfg.Queries, r.cfg.K, time.Now(), r.cfg.Seed)
	if s.Empty() {
		return
	}
	rr := map[string]int{}
	for {
		due := s.PeekDue()
		if d := time.Until(due); d > 0 {
			t := time.NewTimer(d)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return
			}
		} else if ctx.Err() != nil {
			return
		}
		j := s.Next()
		slots := r.byNS[j.Query.Namespace]
		sl := slots[rr[j.Query.Namespace]%len(slots)]
		rr[j.Query.Namespace]++
		r.scheduled.Add(1)
		select {
		case sl.queue <- job{Job: j, slot: sl}:
		default:
			r.dropped.Add(1)
		}
	}
}

func (r *Runner) worker(ctx context.Context, s *slot) {
	for j := range s.queue {
		if ctx.Err() != nil {
			continue // drain: the arm is over
		}
		r.execute(ctx, s, j)
	}
}

// execute runs one scheduled query on its slot.
func (r *Runner) execute(ctx context.Context, s *slot, j job) {
	now := time.Now()
	q := j.Query
	if c := s.current(); c != nil {
		if rep, why := r.cfg.Strategy.Before(now, strategy.ConnState{Created: c.CreatedAt(), LastUsed: s.lastUsed, Queries: c.Queries()}); rep {
			r.retire(s, why)
		}
	}
	if s.current() == nil {
		r.dial(s)
	}
	seq := r.seq.Add(1)
	pid := uint32(0)
	wql := q.WQL
	switch {
	case q.Truth == catalog.TruthPID:
		pid = r.pickPID(s)
		wql = fmt.Sprintf(q.WQL, pid)
	case strings.Contains(q.WQL, "%s"):
		wql = fmt.Sprintf(q.WQL, now.Add(-2*time.Minute).UTC().Format("20060102150405")+".000000+000")
	}
	c := s.current()
	hostPID := (*r.classHost.Load())[q.Class]
	base := r.baseRow(seq, j, s, c, now, hostPID)
	if c == nil {
		r.noconnN.Add(1)
		r.writeQuery(base, wmi.Result{Status: wmi.StatusNoConn, Start: now}, truth.Outcome{Kind: "skipped", Lo: -1, Hi: -1}, pid, true)
		return
	}
	var pre truth.Pre
	if r.cfg.Truth {
		pre = r.tc.Before(q, pid)
	}
	abandon := r.cfg.Strategy.Abandons()
	res := c.Query(ctx, wql, r.cfg.Deadline, abandon, func(late wmi.Result) { r.writeLate(seq, late) })
	s.lastUsed = now
	switch res.Status {
	case wmi.StatusAbandoned:
		r.abandonedN.Add(1)
		r.lateMu.Lock()
		if !r.lateClosed {
			r.latePending[seq] = lateRow{base: base, pid: pid}
		}
		r.lateMu.Unlock()
		if rep, why := r.cfg.Strategy.After(strategy.Outcome{Abandoned: true}); rep {
			r.retire(s, why)
		}
		return
	case wmi.StatusShutdown:
		// The arm ended while the call ran; the call's row is written by the
		// late path if it returns before the probe exits.
		r.lateMu.Lock()
		if !r.lateClosed {
			r.latePending[seq] = lateRow{base: base, pid: pid}
		}
		r.lateMu.Unlock()
		return
	}
	o := truth.Outcome{Kind: "off", Lo: -1, Hi: -1, RegistryCount: -1}
	if r.cfg.Truth && res.Status == wmi.StatusOK {
		o = r.tc.After(q, pre, res)
	} else if res.Status == wmi.StatusOK && q.ImpossibleEmpty && res.RowsN == 0 {
		o.Mask |= truth.S1
	}
	r.writeQuery(base, res, o, pid, true)
	if o.Missing > 0 || o.Phantom > 0 || o.Mismatch > 0 || o.Rebaselined {
		r.writeTruth(seq, q.Key, o)
	}
	impossible := res.Status == wmi.StatusOK && q.ImpossibleEmpty && res.RowsN == 0
	if hostPID != 0 {
		r.hostQMu.Lock()
		r.hostQ[hostPID]++
		r.hostQMu.Unlock()
	}
	var hr, sc uint32
	if res.Err != nil {
		hr, sc = res.Err.HR, res.Err.SCode
	}
	if rep, why := r.cfg.Strategy.After(strategy.Outcome{Errored: res.Status == wmi.StatusError, HR: hr, SCode: sc, ImpossibleEmpty: impossible}); rep {
		r.retire(s, why)
	}
}

// pickPID chooses the proc_pid target from the latest snapshot: 95 % a live
// process, 5 % a recently exited one (negative control, design §3.1).
func (r *Runner) pickPID(s *slot) uint32 {
	p := r.pids.Load()
	if len(p.gone) > 0 && s.rng.Float64() < 0.05 {
		return p.gone[s.rng.Intn(len(p.gone))]
	}
	if len(p.alive) > 0 {
		return p.alive[s.rng.Intn(len(p.alive))]
	}
	return uint32(os.Getpid())
}

// dial makes the slot's next connection, with backoff after failures.
func (r *Runner) dial(s *slot) {
	if time.Now().Before(s.nextDial) {
		return
	}
	opts := wmi.Options{
		Namespace:      s.ns,
		LeakArrays:     r.cfg.Bug == "array-leak",
		CrossApartment: r.cfg.Bug == "cross-apartment",
	}
	gen := s.gen + 1
	var id string
	var once sync.Once
	r.relWG.Add(1)
	released := func() { once.Do(r.relWG.Done) }
	c, ci, err := r.env.Dial(opts, func(outstanding, double int) {
		defer released()
		r.relMu.RLock()
		defer r.relMu.RUnlock()
		if r.relClosed {
			return // after the files closed (release_wait_timeout was logged)
		}
		r.connRow(id, "", s, gen, "release_done", "", wmi.ConnectInfo{}, 0, 0, 0, outstanding, double)
	})
	if err != nil || c == nil {
		released()
		r.connectFails.Add(1)
		s.failStreak++
		back := time.Duration(min(1<<min(s.failStreak-1, 5), 30)) * time.Second
		s.nextDial = time.Now().Add(back)
		r.connRow("", s.prevID, s, gen, "connect_fail", s.reason, ci, 0, 0, 0, -1, -1)
		return
	}
	id = c.ID()
	r.connects.Add(1)
	s.failStreak, s.gen = 0, gen
	r.connRow(id, s.prevID, s, gen, "connect_ok", s.reason, ci, 0, 0, 0, -1, -1)
	s.set(c)
	s.hungWarned.Store(false)
}

// retire closes the slot's connection (the release waits on its thread for
// a running call) and records why.
func (r *Runner) retire(s *slot, reason string) {
	c := s.current()
	if c == nil {
		return
	}
	s.set(nil)
	age := time.Since(c.CreatedAt()).Seconds()
	r.connRow(c.ID(), s.prevID, s, s.gen, "retire", reason, wmi.ConnectInfo{}, c.Queries(), c.Objects(), age, -1, -1)
	c.Close()
	s.prevID = c.ID()
	s.reason = reason
	if reason != "shutdown" {
		r.recycles.Add(1)
		r.recMu.Lock()
		r.recByReason[reason]++
		r.recMu.Unlock()
	}
}

func (r *Runner) totals() map[string]uint64 {
	t := map[string]uint64{
		"queries": r.queries.Load(), "ok": r.okN.Load(), "errors": r.errN.Load(), "abandoned": r.abandonedN.Load(),
		"overloaded": r.overloadedN.Load(), "noconn": r.noconnN.Load(), "connects": r.connects.Load(),
		"connect_fails": r.connectFails.Load(), "recycles": r.recycles.Load(),
		"scheduled": r.scheduled.Load(), "dropped": r.dropped.Load(),
	}
	for i := range r.silent {
		t[fmt.Sprintf("s%d", i+1)] = r.silent[i].Load()
	}
	return t
}

func (r *Runner) recyclesByReason() string {
	r.recMu.Lock()
	defer r.recMu.Unlock()
	keys := make([]string, 0, len(r.recByReason))
	for k := range r.recByReason {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, r.recByReason[k]))
	}
	return strings.Join(parts, ";")
}

func (r *Runner) writeMeta() error {
	b, err := json.MarshalIndent(r.meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(r.cfg.Dir(), "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.cfg.Dir(), "meta.json"))
}

func (r *Runner) abort(reason string) {
	r.abortOnce.Do(func() {
		r.abortReason.Store(reason)
		r.event("abort", "", "", 0, reason)
		r.cancelRun()
	})
}

func (r *Runner) noteWriteErr(err error) {
	if err != nil {
		r.errOnce.Do(func() { r.writeErr = err })
	}
}

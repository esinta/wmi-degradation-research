package runner

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wmiresearch/probe/internal/abort"
	"wmiresearch/probe/internal/catalog"
	"wmiresearch/probe/internal/out"
	"wmiresearch/probe/internal/sampler"
	"wmiresearch/probe/internal/strategy"
	"wmiresearch/probe/internal/sysinfo"
	"wmiresearch/probe/internal/wmi"
)

// fakeConn answers instantly, or sleeps when slow is set.
type fakeConn struct {
	id      string
	created time.Time
	queries atomic.Uint64
	objects atomic.Uint64
	slow    time.Duration
	running atomic.Int64
	closed  atomic.Bool
	onRel   func(int, int)
}

func (c *fakeConn) ID() string           { return c.id }
func (c *fakeConn) CreatedAt() time.Time { return c.created }
func (c *fakeConn) Queries() uint64      { return c.queries.Load() }
func (c *fakeConn) Objects() uint64      { return c.objects.Load() }
func (c *fakeConn) RunningSince() time.Time {
	if ns := c.running.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}
func (c *fakeConn) Close() {
	if c.closed.CompareAndSwap(false, true) && c.onRel != nil {
		c.onRel(0, 0)
	}
}

func (c *fakeConn) Query(ctx context.Context, wql string, deadline time.Duration, abandon bool, late func(wmi.Result)) wmi.Result {
	c.queries.Add(1)
	res := wmi.Result{Status: wmi.StatusOK, Start: time.Now(), Latency: time.Millisecond, EnumRan: true, EnumEndHR: 1,
		Rows: []wmi.Row{{"ProcessId": int32(os.Getpid()), "Name": "x", "InstanceID": "a"}}, RowsN: 1, AptOK: true}
	if c.slow == 0 {
		c.objects.Add(1)
		return res
	}
	done := make(chan wmi.Result, 1)
	c.running.Store(time.Now().UnixNano())
	go func() {
		time.Sleep(c.slow)
		c.running.Store(0)
		done <- res
	}()
	var timeout <-chan time.Time
	if abandon {
		timeout = time.After(deadline)
	}
	select {
	case r := <-done:
		return r
	case <-timeout:
		go func() { r := <-done; r.Status = wmi.StatusAbandoned; late(r) }()
		return wmi.Result{Status: wmi.StatusAbandoned, Start: res.Start}
	case <-ctx.Done():
		go func() { r := <-done; late(r) }()
		return wmi.Result{Status: wmi.StatusShutdown, Start: res.Start}
	}
}

type fakeTruth struct{}

func (fakeTruth) Snapshot() (sysinfo.Snapshot, error) {
	return sysinfo.Snapshot{uint32(os.Getpid()): {PID: uint32(os.Getpid())}}, nil
}
func (fakeTruth) CreateTime(uint32) (int64, bool)            { return 0, false }
func (fakeTruth) ServiceNames(bool) (map[string]bool, error) { return map[string]bool{"x": true}, nil }
func (fakeTruth) RegistryCount(string) (int, error)          { return 1, nil }

type fakeSampler struct{}

func (fakeSampler) Sample() sampler.Sample {
	return sampler.Sample{Time: time.Now(), Snap: sysinfo.Snapshot{uint32(os.Getpid()): {PID: uint32(os.Getpid())}},
		Mem: sysinfo.Memory{TotalPhys: 8 << 30, AvailPhys: 4 << 30, CommitLimit: 8 << 30, CommitTotal: 2 << 30}, DiskFreeGB: 100,
		Canary: time.Millisecond, ClassHost: map[string]uint32{"Win32_Process": 777}}
}

func env(slow time.Duration, conns *[]*fakeConn, mu *sync.Mutex) Env {
	n := 0
	return Env{
		Dial: func(opts wmi.Options, onRel func(int, int)) (Conn, wmi.ConnectInfo, error) {
			mu.Lock()
			defer mu.Unlock()
			n++
			c := &fakeConn{id: fmt.Sprintf("c%d", n), created: time.Now(), slow: slow, onRel: onRel}
			*conns = append(*conns, c)
			return c, wmi.ConnectInfo{Connect: time.Millisecond}, nil
		},
		Truth: fakeTruth{}, Sampler: fakeSampler{},
	}
}

func baseConfig(t *testing.T, arm string) Config {
	st, _ := strategy.Parse("none", 0)
	return Config{
		Arm: arm, Host: "test", OutRoot: t.TempDir(), RunID: "r1", ClientClass: "correct",
		Mix: "production", Queries: catalog.Production(), K: 400, Duration: 1500 * time.Millisecond, Seed: 1,
		Strategy: st, Deadline: time.Second, Cimv2Conns: 3, SampleInterval: 200 * time.Millisecond,
		HangWarn: time.Minute, HangAbort: 0, Truth: true, Limits: abort.Defaults(),
	}
}

func readAll(t *testing.T, dir, base string) [][]string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, base+"-*.csv.gz"))
	var rows [][]string
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(fh)
		if err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(zr).ReadAll()
		fh.Close()
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, recs[1:]...)
	}
	return rows
}

func col(name string) int {
	for i, c := range out.QueryCols {
		if c == name {
			return i
		}
	}
	panic(name)
}

func TestArmRunsAndWritesSchema(t *testing.T) {
	cfg := baseConfig(t, "unit")
	var conns []*fakeConn
	var mu sync.Mutex
	sum, err := Run(context.Background(), cfg, env(0, &conns, &mu))
	end := sum.EndReason
	if err != nil || end != "duration" {
		t.Fatalf("end %q err %v", end, err)
	}
	rows := readAll(t, cfg.Dir(), "queries")
	// k = 400 x ~700/h for 1.5 s ~ 117 queries; allow for scheduling slack.
	if len(rows) < 60 {
		t.Fatalf("only %d query rows", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if len(r) != len(out.QueryCols) {
			t.Fatalf("row has %d columns", len(r))
		}
		if r[col("status")] != "ok" {
			t.Fatalf("status %s", r[col("status")])
		}
		seen[r[col("conn_slot")]] = true
		if r[col("query_key")] == "proc_all" && r[col("host_pid")] != "777" {
			t.Fatalf("attribution not applied: %v", r[col("host_pid")])
		}
	}
	if !seen["cimv2#1"] || !seen["cimv2#3"] {
		t.Fatalf("cimv2 slots used: %v", seen)
	}
	// One connection per slot, never replaced under strategy none.
	mu.Lock()
	n := len(conns)
	mu.Unlock()
	var meta Meta
	b, _ := os.ReadFile(filepath.Join(cfg.Dir(), "meta.json"))
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if n != len(meta.Slots) {
		t.Fatalf("%d connections for %d slots", n, len(meta.Slots))
	}
	if meta.EndReason != "duration" || meta.Totals["queries"] != uint64(len(rows)) || meta.ClientClass != "correct" {
		t.Fatalf("meta %+v", meta)
	}
	conn := readAll(t, cfg.Dir(), "connections")
	events := map[string]int{}
	for _, r := range conn {
		events[r[8]]++
	}
	if events["connect_ok"] != n || events["retire"] != n || events["release_done"] != n {
		t.Fatalf("connection events %v", events)
	}
	if len(readAll(t, cfg.Dir(), "host")) == 0 {
		t.Fatal("no host rows")
	}
}

func TestTimedStrategyRecycles(t *testing.T) {
	cfg := baseConfig(t, "timed")
	cfg.Strategy, _ = strategy.Parse("timed", 300*time.Millisecond)
	var conns []*fakeConn
	var mu sync.Mutex
	if _, err := Run(context.Background(), cfg, env(0, &conns, &mu)); err != nil {
		t.Fatal(err)
	}
	reasons := map[string]int{}
	for _, r := range readAll(t, cfg.Dir(), "connections") {
		if r[8] == "retire" {
			reasons[r[9]]++
		}
	}
	if reasons["timed"] == 0 {
		t.Fatalf("no timed recycles: %v", reasons)
	}
}

func TestAbandonedCallsGetLateRows(t *testing.T) {
	cfg := baseConfig(t, "adaptive")
	cfg.Strategy, _ = strategy.Parse("adaptive", 0)
	cfg.Deadline = 20 * time.Millisecond
	cfg.Queries = catalog.Only(catalog.Production(), []string{"svc"})
	cfg.K = 200 // 30/h x 200 = one query every 0.6 s
	var conns []*fakeConn
	var mu sync.Mutex
	if _, err := Run(context.Background(), cfg, env(60*time.Millisecond, &conns, &mu)); err != nil {
		t.Fatal(err)
	}
	rows := readAll(t, cfg.Dir(), "queries")
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, r := range rows {
		if r[col("status")] != "abandoned" {
			t.Fatalf("status %s", r[col("status")])
		}
		if l, _ := strconv.ParseFloat(r[col("latency_ms")], 64); l < 0 && r[col("truth_kind")] != "still_running" {
			t.Fatalf("late row without latency: %v", r)
		}
	}
	reasons := map[string]int{}
	for _, r := range readAll(t, cfg.Dir(), "connections") {
		if r[8] == "retire" {
			reasons[r[9]]++
		}
	}
	if reasons["adaptive:timeout"] == 0 {
		t.Fatalf("no timeout recycles: %v", reasons)
	}
}

func TestHungCallIsFlagged(t *testing.T) {
	cfg := baseConfig(t, "hung")
	cfg.Queries = catalog.Only(catalog.Production(), []string{"svc"})
	cfg.K = 1000
	cfg.HangWarn, cfg.HangAbort = 300*time.Millisecond, 700*time.Millisecond
	cfg.Duration = 5 * time.Second
	var conns []*fakeConn
	var mu sync.Mutex
	sum, err := Run(context.Background(), cfg, env(10*time.Second, &conns, &mu))
	if err != nil {
		t.Fatal(err)
	}
	end := sum.EndReason
	if end[:6] != "abort:" {
		t.Fatalf("end %q", end)
	}
	kinds := map[string]int{}
	for _, r := range readAll(t, cfg.Dir(), "events") {
		kinds[r[1]]++
	}
	if kinds["hung"] == 0 || kinds["abort"] != 1 {
		t.Fatalf("events %v", kinds)
	}
}

func TestBuggyArmsAreFenced(t *testing.T) {
	cfg := baseConfig(t, "st2")
	cfg.ClientClass, cfg.Bug = "buggy", "array-leak"
	if err := cfg.Validate(); err == nil {
		t.Fatal("buggy arm without buggy- prefix accepted")
	}
	cfg.Arm = "buggy-st2"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.ClientClass, cfg.Bug = "correct", ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("correct arm with buggy- prefix accepted")
	}
	cfg.Arm, cfg.Bug = "x", "array-leak"
	if err := cfg.Validate(); err == nil {
		t.Fatal("correct arm with a bug accepted")
	}
}

func TestRunDirIsNeverReused(t *testing.T) {
	cfg := baseConfig(t, "once")
	cfg.Duration = 100 * time.Millisecond
	var conns []*fakeConn
	var mu sync.Mutex
	if _, err := Run(context.Background(), cfg, env(0, &conns, &mu)); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), cfg, env(0, &conns, &mu)); err == nil {
		t.Fatal("second run into the same directory accepted")
	}
}

// Package preflight runs the per-host checks before the first arm (design
// §8): isolation and identity, an idle baseline, which catalog namespaces
// exist, the static provider attribution map, WMI quotas and cache control,
// the H-enum check, the provider-host unload timing, and optionally the k
// calibration ramp. Its output, preflight.json, feeds `probe2 run
// -preflight`.
package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"wmiresearch/probe/internal/abort"
	"wmiresearch/probe/internal/catalog"
	"wmiresearch/probe/internal/hresult"
	"wmiresearch/probe/internal/isolation"
	"wmiresearch/probe/internal/out"
	"wmiresearch/probe/internal/runner"
	"wmiresearch/probe/internal/sampler"
	"wmiresearch/probe/internal/strategy"
	"wmiresearch/probe/internal/sysinfo"
	"wmiresearch/probe/internal/wmi"
)

// Config for a pre-flight.
type Config struct {
	OutRoot     string
	Host        string
	RunID       string
	Idle        time.Duration
	UnloadWatch time.Duration
	Ramp        []float64
	RampStep    time.Duration
	RampBudget  float64 // max mean induced CPU % for k_H
	Commit      string
	Priority    string
	Log         func(format string, args ...any)
}

// Provider is one class's attribution.
type Provider struct {
	Namespace    string `json:"namespace"`
	Provider     string `json:"provider"` // "" = repository
	HostingModel string `json:"hosting_model,omitempty"`
	CLSID        string `json:"clsid,omitempty"`
	DLL          string `json:"dll,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Namespace is one namespace's presence.
type Namespace struct {
	Present bool   `json:"present"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

// HEnum is the result of the H-enum check (design §2.2).
type HEnum struct {
	Query           string `json:"query"`
	StrictStatus    string `json:"strict_status"`
	StrictErrOp     string `json:"strict_err_op,omitempty"`
	StrictCode      string `json:"strict_code,omitempty"`
	StrictEnumEnd   string `json:"strict_enum_end_hr,omitempty"`
	ForEachExecErr  string `json:"foreach_exec_err,omitempty"`
	ForEachErr      string `json:"foreach_err,omitempty"`
	ForEachItems    int    `json:"foreach_items"`
	ForEachReportOK bool   `json:"foreach_reports_success"`
	Verdict         string `json:"verdict"`
}

// Unload is one provider host's exit after the probe went idle.
type Unload struct {
	PID          uint32  `json:"pid"`
	Label        string  `json:"label"`
	ExitAfterSec float64 `json:"exit_after_idle_s"` // -1 = still running at the end of the watch
}

// RampStep is one calibration step.
type RampStep struct {
	K              float64 `json:"k"`
	EndReason      string  `json:"end_reason"`
	MeanInducedCPU float64 `json:"mean_induced_cpu_pct"`
	MeanHostCPU    float64 `json:"mean_host_cpu_pct"`
	Queries        uint64  `json:"queries"`
	Dropped        uint64  `json:"dropped"`
	Errors         uint64  `json:"errors"`
	Dir            string  `json:"dir"`
}

// Result is preflight.json.
type Result struct {
	RunID        string               `json:"run_id"`
	ProbeCommit  string               `json:"probe_commit"`
	Priority     string               `json:"priority_class"`
	StartUTC     time.Time            `json:"start_utc"`
	EndUTC       time.Time            `json:"end_utc"`
	OS           sysinfo.OSInfo       `json:"os"`
	Account      string               `json:"account"`
	Isolation    []isolation.Finding  `json:"isolation_findings"`
	WinmgmtPID   uint32               `json:"winmgmt_pid"`
	WinmgmtHost  []string             `json:"winmgmt_host_services"`
	Namespaces   map[string]Namespace `json:"namespaces"`
	Providers    map[string]Provider  `json:"providers"` // by class
	Attribution  map[string]string    `json:"attribution"`
	Quotas       []map[string]string  `json:"provider_host_quotas"`
	CacheControl []map[string]string  `json:"cache_control"`
	HEnum        HEnum                `json:"h_enum"`
	Unloads      []Unload             `json:"unloads"`
	Ramp         []RampStep           `json:"ramp,omitempty"`
	KH           float64              `json:"k_h,omitempty"`
	Notes        []string             `json:"notes,omitempty"`
}

// Run executes the pre-flight and writes preflight.json in its directory.
func Run(ctx context.Context, cfg Config) (*Result, string, error) {
	log := cfg.Log
	if log == nil {
		log = func(string, ...any) {}
	}
	dir := filepath.Join(cfg.OutRoot, cfg.Host, "preflight", cfg.RunID)
	if _, err := os.Stat(dir); err == nil {
		return nil, "", fmt.Errorf("%s exists", dir)
	}
	ws, err := out.NewSet(dir, map[string][]string{"procs": out.ProcCols, "events": out.EventCols})
	if err != nil {
		return nil, "", err
	}
	defer ws.Close()

	res := &Result{RunID: cfg.RunID, ProbeCommit: cfg.Commit, Priority: cfg.Priority, StartUTC: time.Now().UTC(), OS: sysinfo.GetOSInfo(runtime.NumCPU()),
		Namespaces: map[string]Namespace{}, Providers: map[string]Provider{}, Attribution: map[string]string{}}
	res.Account, _ = sysinfo.Account(uint32(os.Getpid()))
	res.Isolation, _ = isolation.Check()
	if pid, err := sysinfo.ServicePID("Winmgmt"); err == nil {
		res.WinmgmtPID = pid
		res.WinmgmtHost, _ = sysinfo.ServicesInProcess(pid)
		sort.Strings(res.WinmgmtHost)
		if len(res.WinmgmtHost) > 1 {
			res.Notes = append(res.Notes, fmt.Sprintf("Winmgmt shares its svchost with %d other services: its process metrics are contaminated (design §7: winmgmt /standalonehost)", len(res.WinmgmtHost)-1))
		}
	}
	if !strings.EqualFold(res.Account, `NT AUTHORITY\SYSTEM`) {
		res.Notes = append(res.Notes, "not running as LocalSystem (Esinta's account); Defender and Security-log queries may be denied")
	}

	smp := sampler.New(dir, nil)
	write := func(s sampler.Sample) {
		for _, r := range s.ProcRows {
			_ = ws.W("procs").Write(r)
		}
		for _, e := range s.Events {
			_ = ws.W("events").Write(e)
		}
	}

	// 1. Idle baseline: what WMI looks like before the probe touches it.
	log("idle baseline: %s", cfg.Idle)
	if !sleepSampling(ctx, cfg.Idle, 10*time.Second, smp, write) {
		return finish(res, dir, "interrupted")
	}

	// 2. Namespaces, providers, quotas, H-enum: one short-lived connection
	// per namespace, closed before the unload watch.
	conns := map[string]*wmi.Conn{}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	qs := catalog.Production()
	for _, ns := range append(catalog.Namespaces(qs), `root`) {
		c, ci, err := wmi.Dial(wmi.Options{Namespace: ns})
		if err != nil {
			code := ""
			if ci.Err != nil {
				code = hresult.Name(hresult.Effective(ci.Err.HR, ci.Err.SCode))
			}
			res.Namespaces[ns] = Namespace{Present: false, Code: code, Error: err.Error()}
			log("namespace %s: absent (%s)", ns, code)
			continue
		}
		res.Namespaces[ns] = Namespace{Present: true}
		conns[ns] = c
	}
	for _, q := range qs {
		if _, done := res.Providers[q.Class]; done {
			continue
		}
		c := conns[q.Namespace]
		if c == nil {
			continue
		}
		p := Provider{Namespace: q.Namespace}
		prov, ei := c.ClassProvider(q.Class)
		if ei != nil {
			p.Error = ei.Op + ": " + ei.Text
		}
		p.Provider = prov
		if prov != "" {
			r := c.Query(ctx, fmt.Sprintf("SELECT Name, HostingModel, CLSID FROM __Win32Provider WHERE Name = '%s'", strings.ReplaceAll(prov, "'", "")), time.Minute, false, nil)
			if len(r.Rows) > 0 {
				p.HostingModel = str(r.Rows[0]["HostingModel"])
				p.CLSID = str(r.Rows[0]["CLSID"])
				if dll, err := sysinfo.CLSIDServer(p.CLSID); err == nil {
					p.DLL = dll
					res.Attribution[q.Class] = dll
				}
			} else if r.Err != nil {
				p.Error = r.Err.Op + ": " + r.Err.Text
			}
		}
		res.Providers[q.Class] = p
		log("class %s: provider %q hosting %q dll %q", q.Class, p.Provider, p.HostingModel, p.DLL)
	}
	if c := conns[`root`]; c != nil {
		res.Quotas = rows(c.Query(ctx, "SELECT * FROM __ProviderHostQuotaConfiguration", time.Minute, false, nil))
		res.CacheControl = rows(c.Query(ctx, "SELECT * FROM __CacheControl", time.Minute, false, nil))
	}
	if c := conns[catalog.NSCimv2]; c != nil {
		res.HEnum = hEnum(ctx, c)
		log("H-enum: %s", res.HEnum.Verdict)
	}

	// 3. Unload watch: release everything, then watch the provider hosts.
	for ns, c := range conns {
		c.Close()
		delete(conns, ns)
	}
	idleSince := time.Now()
	log("unload watch: %s", cfg.UnloadWatch)
	first := smp.Sample()
	write(first)
	alive := map[uint32]string{}
	for _, r := range first.ProcRows {
		if r[1] == "wmiprvse" {
			alive[atou(r[2])] = r[6]
		}
	}
	exited := map[uint32]float64{}
	deadline := time.Now().Add(cfg.UnloadWatch)
	for time.Now().Before(deadline) && len(exited) < len(alive) {
		if !sleepCtx(ctx, 5*time.Second) {
			break
		}
		s := smp.Sample()
		write(s)
		for pid := range alive {
			if _, gone := exited[pid]; gone {
				continue
			}
			if p, ok := s.Snap[pid]; !ok || !strings.EqualFold(p.Name, "WmiPrvSE.exe") {
				exited[pid] = time.Since(idleSince).Seconds()
			}
		}
	}
	for pid, label := range alive {
		u := Unload{PID: pid, Label: label, ExitAfterSec: -1}
		if t, ok := exited[pid]; ok {
			u.ExitAfterSec = t
		}
		res.Unloads = append(res.Unloads, u)
	}
	sort.Slice(res.Unloads, func(i, j int) bool { return res.Unloads[i].PID < res.Unloads[j].PID })

	// 4. Optional k calibration ramp (design §3.2): the production mix,
	// strategy none, truth on, as in the real arms.
	if len(cfg.Ramp) > 0 && ctx.Err() == nil {
		skip := absent(res)
		st, _ := strategy.Parse("none", 0)
		for _, k := range cfg.Ramp {
			log("ramp k=%g for %s", k, cfg.RampStep)
			rc := runner.Config{
				Arm: fmt.Sprintf("ramp-k%g", k), Host: cfg.Host, OutRoot: filepath.Join(cfg.OutRoot, cfg.Host, "preflight", cfg.RunID, "ramp"),
				RunID: time.Now().UTC().Format("20060102T150405Z"), ClientClass: "correct", Mix: "production",
				Queries: catalog.Without(catalog.Production(), skip), K: k, Duration: cfg.RampStep, Seed: 1,
				Strategy: st, Deadline: 30 * time.Second, Cimv2Conns: 3, SampleInterval: 10 * time.Second,
				HangWarn: 10 * time.Minute, HangAbort: 30 * time.Minute, Truth: true, Attribution: res.Attribution,
				Limits: abort.Defaults(), Commit: cfg.Commit, Priority: cfg.Priority,
			}
			sum, err := runner.Run(ctx, rc, runner.NativeEnv(rc.OutRoot, res.Attribution))
			step := RampStep{K: k, EndReason: sum.EndReason, MeanInducedCPU: sum.MeanInducedCPU, MeanHostCPU: sum.MeanHostCPU,
				Queries: sum.Totals["queries"], Dropped: sum.Totals["dropped"], Errors: sum.Totals["errors"], Dir: sum.Dir}
			if err != nil {
				step.EndReason += " / " + err.Error()
			}
			res.Ramp = append(res.Ramp, step)
			log("  induced CPU %.1f %%, host %.1f %%, %d queries, %d dropped, end %s", step.MeanInducedCPU, step.MeanHostCPU, step.Queries, step.Dropped, step.EndReason)
			if step.EndReason != "duration" || step.MeanInducedCPU > cfg.RampBudget || step.Dropped > 0 {
				break
			}
			res.KH = k
		}
		if res.KH < 10 {
			res.Notes = append(res.Notes, fmt.Sprintf("k_H = %g < 10: acceleration too weak on this host (design §3.2); report and fall back to the long-run plan", res.KH))
		}
	}
	return finish(res, dir, "")
}

func finish(res *Result, dir, note string) (*Result, string, error) {
	if note != "" {
		res.Notes = append(res.Notes, note)
	}
	res.EndUTC = time.Now().UTC()
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return res, dir, err
	}
	return res, dir, os.WriteFile(filepath.Join(dir, "preflight.json"), b, 0o644)
}

// absent lists the namespaces pre-flight found missing.
func absent(res *Result) []string {
	var out []string
	for ns, n := range res.Namespaces {
		if !n.Present && ns != `root` {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

// Load reads a preflight.json.
func Load(path string) (*Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Absent is the exported form of absent, for `run -preflight`.
func (r *Result) Absent() []string { return absent(r) }

// hEnum runs the same failing query both ways (design §2.2).
func hEnum(ctx context.Context, c *wmi.Conn) HEnum {
	const q = "SELECT * FROM Win32_NoSuchClass_Probe2"
	h := HEnum{Query: q}
	r := c.Query(ctx, q, time.Minute, false, nil)
	h.StrictStatus = string(r.Status)
	if r.Err != nil {
		h.StrictErrOp = r.Err.Op
		h.StrictCode = hresult.Name(hresult.Effective(r.Err.HR, r.Err.SCode))
	}
	if r.EnumRan {
		h.StrictEnumEnd = hresult.Name(r.EnumEndHR)
	}
	fe := c.QueryForEach(q)
	h.ForEachItems = fe.Items
	if fe.ExecErr != nil {
		h.ForEachExecErr = fe.ExecErr.Op + ": " + hresult.Name(hresult.Effective(fe.ExecErr.HR, fe.ExecErr.SCode))
	}
	if fe.ForEachErr != nil {
		h.ForEachErr = hresult.Name(hresult.Effective(fe.ForEachErr.HR, fe.ForEachErr.SCode))
	}
	h.ForEachReportOK = fe.ExecErr == nil && fe.ForEachErr == nil
	switch {
	case h.ForEachReportOK && r.Status == wmi.StatusError:
		h.Verdict = fmt.Sprintf("CONFIRMED: oleutil.ForEach reports success with %d items; the strict loop sees %s at %s", fe.Items, h.StrictCode, h.StrictErrOp)
	case r.Status == wmi.StatusError && h.StrictErrOp == "ExecQuery":
		h.Verdict = "REFUTED for this case: the error surfaces at ExecQuery (" + h.StrictCode + "), so ForEach is never reached"
	case r.Status == wmi.StatusOK:
		h.Verdict = "UNEXPECTED: the invalid class query succeeded"
	default:
		h.Verdict = fmt.Sprintf("OTHER: strict %s at %s; ForEach exec %q foreach %q", h.StrictCode, h.StrictErrOp, h.ForEachExecErr, h.ForEachErr)
	}
	return h
}

func rows(r wmi.Result) []map[string]string {
	var out []map[string]string
	for _, row := range r.Rows {
		m := map[string]string{}
		for k, v := range row {
			m[k] = str(v)
		}
		out = append(out, m)
	}
	if r.Err != nil {
		out = append(out, map[string]string{"error": r.Err.Op + ": " + r.Err.Text})
	}
	return out
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func atou(s string) uint32 {
	var n uint32
	fmt.Sscan(s, &n)
	return n
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func sleepSampling(ctx context.Context, total, every time.Duration, s *sampler.Sampler, write func(sampler.Sample)) bool {
	end := time.Now().Add(total)
	write(s.Sample())
	for time.Now().Before(end) {
		if !sleepCtx(ctx, min(every, time.Until(end))) {
			return false
		}
		write(s.Sample())
	}
	return true
}

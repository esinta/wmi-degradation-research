package runner

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"wmiresearch/probe/internal/abort"
	"wmiresearch/probe/internal/etw"
	"wmiresearch/probe/internal/hresult"
	"wmiresearch/probe/internal/truth"
	"wmiresearch/probe/internal/wmi"
)

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 3, 64)
}

func itoa[T ~int | ~int32 | ~int64 | ~uint32 | ~uint64](v T) string {
	return strconv.FormatInt(int64(v), 10)
}

// baseRow fills the columns known before the call: run_id ... host_query_n.
func (r *Runner) baseRow(seq uint64, j job, s *slot, c Conn, now time.Time, hostPID uint32) []string {
	connID, n, objs, age := "", "", "", ""
	if c != nil {
		connID = c.ID()
		n = itoa(c.Queries() + 1)
		objs = itoa(c.Objects())
		age = strconv.FormatFloat(now.Sub(c.CreatedAt()).Seconds(), 'f', 3, 64)
	}
	hq := ""
	if hostPID != 0 {
		r.hostQMu.Lock()
		hq = itoa(r.hostQ[hostPID] + 1)
		r.hostQMu.Unlock()
	}
	hp := ""
	if hostPID != 0 {
		hp = itoa(hostPID)
	}
	return []string{
		r.cfg.RunID, r.cfg.Arm, itoa(seq), ts(now), ms(now.Sub(j.Due)),
		connID, s.name, itoa(s.gen), s.ns, j.Query.Key,
		n, objs, age, hp, hq,
	}
}

// writeQuery completes and writes a query row. count updates the status
// counters; late rows of abandoned calls were counted when the caller gave
// up and pass false.
func (r *Runner) writeQuery(base []string, res wmi.Result, o truth.Outcome, pid uint32, count bool) {
	if count {
		r.queries.Add(1)
		switch res.Status {
		case wmi.StatusOK:
			r.okN.Add(1)
		case wmi.StatusError:
			r.errN.Add(1)
		case wmi.StatusOverloaded:
			r.overloadedN.Add(1)
		}
	}
	mask := truth.Mask(res, o)
	for i := range r.silent {
		if mask&(1<<i) != 0 {
			r.silent[i].Add(1)
		}
	}
	e := res.Err
	if e == nil {
		e = &wmi.ErrInfo{}
	}
	hexOr := func(v uint32, set bool) string {
		if !set {
			return ""
		}
		return hresult.Hex(v)
	}
	hasErr := res.Err != nil
	eff := hresult.Effective(e.HR, e.SCode)
	tpid := ""
	if pid != 0 {
		tpid = itoa(pid)
	}
	bound := func(v int) string {
		if v < 0 {
			return ""
		}
		return itoa(v)
	}
	row := append(base,
		itoa(r.cfg.Deadline.Milliseconds()), ms(res.Latency), ms(res.Exec), ms(res.FirstRow), ms(res.Enum),
		itoa(res.RowsN), itoa(len(res.Rows)), itoa(res.PropsRead), itoa(res.ArrayProps), itoa(res.ArrayN),
		string(res.Status), hexOr(e.HR, hasErr), hexOr(e.SCode, hasErr && e.SCode != 0), strconv.Itoa(int(e.WCode)),
		hexOr(eff, hasErr), e.Op, e.Src, e.Text,
		hexOr(res.EnumEndHR, res.EnumRan),
		itoa(res.ItemsSkipped), itoa(res.PropsFailed), itoa(res.Panics),
		itoa(res.TID), strconv.Itoa(res.AptType), strconv.FormatBool(res.AptOK),
		itoa(res.LedgerAcquired), itoa(res.LedgerOutstanding), itoa(res.LedgerDouble), itoa(res.LedgerLeaked),
		tpid, o.Kind, bound(o.Lo), bound(o.Hi), itoa(o.Missing), itoa(o.Phantom), itoa(o.Mismatch), itoa(mask),
		itoa(r.canaryUS.Load()),
	)
	r.noteWriteErr(r.ws.W("queries").Write(row))
}

func (lr lateRow) status() wmi.Status {
	if lr.shutdown {
		return wmi.StatusShutdown
	}
	return wmi.StatusAbandoned
}

// writeLate writes the row of an abandoned call once WMI answered.
func (r *Runner) writeLate(seq uint64, res wmi.Result) {
	r.lateMu.Lock()
	lr, ok := r.latePending[seq]
	if ok {
		delete(r.latePending, seq)
	}
	closed := r.lateClosed
	r.lateMu.Unlock()
	if !ok || closed {
		return
	}
	res.Status = lr.status()
	r.writeQuery(append([]string(nil), lr.base...), res, truth.Outcome{Kind: "late", Lo: -1, Hi: -1}, lr.pid, false)
}

// flushLate writes the abandoned calls still running at the end, with
// status abandoned and no latency.
func (r *Runner) flushLate() {
	r.lateMu.Lock()
	pend := r.latePending
	r.latePending = map[uint64]lateRow{}
	r.lateClosed = true
	r.lateMu.Unlock()
	seqs := make([]uint64, 0, len(pend))
	for s := range pend {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, s := range seqs {
		lr := pend[s]
		res := wmi.Result{Status: lr.status(), Latency: -time.Millisecond}
		r.writeQuery(append([]string(nil), lr.base...), res, truth.Outcome{Kind: "still_running", Lo: -1, Hi: -1}, lr.pid, false)
	}
}

func (r *Runner) writeTruth(seq uint64, key string, o truth.Outcome) {
	note := o.Note
	if o.Rebaselined {
		note = strings.TrimSpace(note + " rebaselined")
	}
	reg := ""
	if o.RegistryCount >= 0 {
		reg = itoa(o.RegistryCount)
	}
	r.noteWriteErr(r.ws.W("truth").Write([]string{
		ts(time.Now()), itoa(seq), key, o.Kind, strings.Join(o.MissingKeys, ";"), strings.Join(o.PhantomKeys, ";"), reg, note,
	}))
}

func (r *Runner) connRow(id, prev string, s *slot, gen int, event, reason string, ci wmi.ConnectInfo, queries, objects uint64, age float64, outstanding, double int) {
	e := ci.Err
	if e == nil {
		e = &wmi.ErrInfo{}
	}
	hx := func(v uint32) string {
		if v == 0 {
			return ""
		}
		return hresult.Hex(v)
	}
	opt := func(v int) string {
		if v < 0 {
			return ""
		}
		return itoa(v)
	}
	ageS := ""
	if age > 0 {
		ageS = strconv.FormatFloat(age, 'f', 3, 64)
	}
	durOr := func(d time.Duration) string {
		if d == 0 {
			return ""
		}
		return ms(d)
	}
	r.noteWriteErr(r.ws.W("connections").Write([]string{
		r.cfg.RunID, r.cfg.Arm, ts(time.Now()), id, prev, s.name, itoa(gen), s.ns,
		event, reason, durOr(ci.STAStart), durOr(ci.Connect), durOr(ci.Security),
		hx(e.HR), hx(e.SCode), strconv.Itoa(int(e.WCode)), e.Op, e.Text,
		itoa(queries), itoa(objects), ageS, opt(outstanding), opt(double),
	}))
}

func (r *Runner) event(kind, slot, connID string, pid uint32, detail string) {
	p := ""
	if pid != 0 {
		p = itoa(pid)
	}
	r.noteWriteErr(r.ws.W("events").Write([]string{ts(time.Now()), kind, slot, connID, p, detail}))
}

// sampleLoop samples every SampleInterval until sampCtx ends (which is after
// the release test). Abort and hang checks apply while runCtx is live.
func (r *Runner) sampleLoop(sampCtx, runCtx context.Context) {
	t := time.NewTicker(r.cfg.SampleInterval)
	defer t.Stop()
	ab := abort.New(r.cfg.Limits)
	for {
		select {
		case <-sampCtx.Done():
			return
		case <-t.C:
		}
		smp := r.sampleOnce()
		if runCtx.Err() != nil || smp == nil {
			continue
		}
		r.cpuHost += smp.hostCPU
		r.cpuInduced += smp.inducedCPU
		r.cpuN++
		r.checkHangs()
		if reason := ab.Check(time.Now(), r.abortInput(smp)); reason != "" {
			r.abort(reason)
		}
	}
}

type sampleView struct {
	availPhysMB, availPhysPct, commitPct, hostCPU, inducedCPU, diskGB float64
	winmgmtMB, winmgmtHandles, probeMB, probeHandles                  float64
	wmiprvse                                                          int
}

func (r *Runner) sampleOnce() *sampleView {
	smp := r.env.Sampler.Sample()
	if smp.Err != nil {
		r.event("sample_error", "", "", 0, smp.Err.Error())
		return nil
	}
	r.canaryUS.Store(smp.Canary.Microseconds())
	for _, row := range smp.ProcRows {
		r.noteWriteErr(r.ws.W("procs").Write(row))
	}
	for _, ev := range smp.Events {
		r.noteWriteErr(r.ws.W("events").Write(ev))
	}
	// PID pool for proc_pid targets.
	prev := r.pids.Load()
	np := &pidPool{}
	for pid := range smp.Snap {
		if pid > 4 {
			np.alive = append(np.alive, pid)
		}
	}
	np.gone = append(np.gone, prev.gone...)
	for _, pid := range prev.alive {
		if _, ok := smp.Snap[pid]; !ok {
			np.gone = append(np.gone, pid)
		}
	}
	if len(np.gone) > 200 {
		np.gone = np.gone[len(np.gone)-200:]
	}
	r.pids.Store(np)
	ch := smp.ClassHost
	r.classHost.Store(&ch)

	v := &sampleView{hostCPU: smp.HostCPU, inducedCPU: smp.InducedCPU, diskGB: smp.DiskFreeGB, wmiprvse: smp.WmiPrvSE}
	if smp.Mem.TotalPhys > 0 {
		v.availPhysMB = float64(smp.Mem.AvailPhys) / (1 << 20)
		v.availPhysPct = 100 * float64(smp.Mem.AvailPhys) / float64(smp.Mem.TotalPhys)
	}
	if smp.Mem.CommitLimit > 0 {
		v.commitPct = 100 * float64(smp.Mem.CommitTotal) / float64(smp.Mem.CommitLimit)
	}
	if smp.WinmgmtOK {
		v.winmgmtMB, v.winmgmtHandles = float64(smp.Winmgmt.Private)/(1<<20), float64(smp.Winmgmt.Handles)
	}
	v.probeMB, v.probeHandles = float64(smp.Probe.Private)/(1<<20), float64(smp.Probe.Handles)

	etwOn, lost := "", ""
	if r.env.Meter != nil {
		d := r.env.Meter.Drain()
		etwOn, lost = strconv.FormatBool(d.On), itoa(d.Lost)
		r.wmiOpsSelf += d.Self
		r.wmiOpsForeign += d.Foreign
		r.wmiOpsInternal += d.Internal
		for _, c := range WmiOpsRows(smp.Time, d) {
			r.noteWriteErr(r.ws.W("wmiops").Write(c))
		}
		if d.Enabling != "" {
			r.event("etw_error", "", "", 0, d.Enabling)
		}
	}

	running, _ := wmi.CallStats()
	f := func(x float64) string { return strconv.FormatFloat(x, 'f', 2, 64) }
	r.noteWriteErr(r.ws.W("host").Write([]string{
		ts(smp.Time), f(smp.HostCPU), f(smp.InducedCPU), f(v.availPhysMB), f(v.availPhysPct),
		itoa(smp.Mem.CommitTotal >> 20), itoa(smp.Mem.CommitLimit >> 20), f(smp.DiskFreeGB), itoa(smp.Canary.Microseconds()),
		itoa(r.queries.Load()), itoa(r.okN.Load()), itoa(r.errN.Load()), itoa(r.abandonedN.Load()), itoa(r.overloadedN.Load()),
		itoa(r.noconnN.Load()), itoa(r.hungNow.Load()), itoa(running),
		itoa(r.silent[0].Load()), itoa(r.silent[1].Load()), itoa(r.silent[2].Load()), itoa(r.silent[3].Load()), itoa(r.silent[4].Load()),
		itoa(r.connects.Load()), itoa(r.connectFails.Load()), itoa(r.recycles.Load()), r.recyclesByReason(),
		itoa(smp.WmiPrvSE), itoa(smp.Exits), itoa(r.scheduled.Load()), itoa(r.dropped.Load()),
		etwOn, itoa(r.wmiOpsSelf), itoa(r.wmiOpsForeign), lost, itoa(r.wmiOpsInternal),
	}))
	return v
}

func (r *Runner) abortInput(v *sampleView) abort.Input {
	return abort.Input{
		AvailPhysPct: v.availPhysPct, AvailPhysMB: v.availPhysMB, CommitPct: v.commitPct,
		HostCPUPct: v.hostCPU, InducedCPUPct: v.inducedCPU, DiskFreeGB: v.diskGB,
		WinmgmtPrivateMB: v.winmgmtMB, WinmgmtHandles: v.winmgmtHandles, WmiPrvSE: v.wmiprvse,
		ProbePrivateMB: v.probeMB, ProbeHandles: v.probeHandles, Goroutines: runtime.NumGoroutine(),
		Scheduled: r.scheduled.Load(), Dropped: r.dropped.Load(),
	}
}

// checkHangs flags calls running longer than HangWarn and aborts at
// HangAbort (strategies that do not abandon wait for every call, so a hung
// call would otherwise stop the slot silently). A hung connection is itself
// a result (design §9).
func (r *Runner) checkHangs() {
	hung := int64(0)
	for _, s := range r.slots {
		c := s.current()
		if c == nil {
			continue
		}
		since := c.RunningSince()
		if since.IsZero() {
			continue
		}
		d := time.Since(since)
		if d >= r.cfg.HangWarn {
			hung++
			if s.hungWarned.CompareAndSwap(false, true) {
				r.event("hung", s.name, c.ID(), 0, fmt.Sprintf("call running for %s", d.Round(time.Second)))
			}
		}
		if r.cfg.HangAbort > 0 && d >= r.cfg.HangAbort {
			r.abort(fmt.Sprintf("hung call on %s for %s", s.name, d.Round(time.Second)))
		}
	}
	r.hungNow.Store(hung)
}

// Totals is exported for the CLI summary.
func (r *Runner) Totals() map[string]uint64 { return r.totals() }

// WmiOpsRows renders one meter drain as wmiops rows (clients with ops > 0).
func WmiOpsRows(at time.Time, d etw.Drained) [][]string {
	var rows [][]string
	for _, c := range d.Counts {
		if c.Ops == 0 {
			continue
		}
		rows = append(rows, []string{ts(at), strconv.FormatFloat(d.OnFor.Seconds(), 'f', 1, 64), itoa(c.ClientPID), c.Image,
			strconv.FormatBool(c.Local), strconv.FormatBool(c.Self), strconv.FormatBool(c.Internal), itoa(c.Ops), c.Sample, c.User, c.SampleNS})
	}
	return rows
}

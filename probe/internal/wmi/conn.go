package wmi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"wmiresearch/probe/internal/clock"
	"wmiresearch/probe/internal/ledger"
	"wmiresearch/probe/internal/sta"
)

const (
	wbemFlagReturnImmediately = 0x10
	wbemFlagForwardOnly       = 0x20

	// Security levels exactly as Esinta's setSecurity sets them. Esinta's
	// code calls 3 "Packet", but for SWbemSecurity.AuthenticationLevel 3 is
	// wbemAuthenticationLevelCall; copied as is to match production.
	authLevel = 3
	impLevel  = 3 // wbemImpersonationLevelImpersonate
)

var (
	inFlight  atomic.Int32
	abandoned atomic.Uint64
)

// CallStats reports calls running now and calls abandoned so far, across
// all connections.
func CallStats() (running int32, abandonedTotal uint64) {
	return inFlight.Load(), abandoned.Load()
}

// Per-call ownership of the result (as Esinta's callPending/... states).
const (
	callPending int32 = iota
	callDelivered
	callAbandoned
)

// Conn is one WMI connection: a locator and a service living in their own
// STA thread's apartment.
type Conn struct {
	id        string
	opts      Options
	thread    *sta.Thread
	createdAt time.Time

	// COM state: touched only on thread.
	connLedger *ledger.Ledger
	locator    *ole.IDispatch
	locTok     uint64
	serviceVar *owned
	service    *ole.IDispatch

	closed       atomic.Bool
	queries      atomic.Uint64
	objects      atomic.Uint64
	runningSince atomic.Int64 // unix nanos of the running call's start, 0 when idle

	// OnReleased is called on the connection's thread after the COM objects
	// were released, with the connection-scope ledger counts.
	OnReleased func(outstanding, double int)
}

// Dial creates a connection: a new STA thread, then SWbemLocator,
// ConnectServer and security setup on it. On failure the thread is stopped
// and the error is returned in ConnectInfo.Err as well.
func Dial(opts Options) (*Conn, ConnectInfo, error) {
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 60 * time.Second
	}
	var ci ConnectInfo
	t0 := clock.Now()
	mode := sta.ModeSTA
	if opts.CrossApartment {
		mode = sta.ModeMTA
	}
	th, err := sta.New(mode)
	ci.STAStart = clock.Since(t0)
	if err != nil {
		ci.Err = &ErrInfo{Op: "STA", Text: truncate(err.Error(), 200)}
		return nil, ci, err
	}
	c := &Conn{id: newID(), opts: opts, thread: th, createdAt: time.Now(), connLedger: ledger.New()}

	done := make(chan ConnectInfo, 1)
	if !th.Submit(func() { done <- c.connect() }) {
		th.Stop()
		ci.Err = &ErrInfo{Op: "Connect", Text: "connection thread rejected work"}
		return nil, ci, errors.New(ci.Err.Text)
	}
	timer := time.NewTimer(opts.ConnectTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		ci.Connect, ci.Security, ci.Err = r.Connect, r.Security, r.Err
	case <-timer.C:
		ci.Err = &ErrInfo{Op: "Connect", Text: fmt.Sprintf("no answer within %s", opts.ConnectTimeout)}
	}
	if ci.Err != nil {
		c.Close() // release queues behind a still-running connect
		return nil, ci, fmt.Errorf("%s: %s", ci.Err.Op, ci.Err.Text)
	}
	c.createdAt = time.Now()
	return c, ci, nil
}

// connect runs on the connection's thread.
func (c *Conn) connect() (ci ConnectInfo) {
	defer func() {
		if r := recover(); r != nil {
			ci.Err = &ErrInfo{Op: "Connect", Text: truncate(fmt.Sprint("panic: ", r), 200)}
		}
	}()
	l := c.connLedger
	t0 := clock.Now()
	unk, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		ci.Err = errInfo("CreateObject", err)
		return
	}
	tokU := l.Acquire("locator-unknown")
	loc, err := unk.QueryInterface(ole.IID_IDispatch)
	if l.Release(tokU) {
		unk.Release()
	}
	if err != nil {
		ci.Err = errInfo("QueryInterface", err)
		return
	}
	c.locator, c.locTok = loc, l.Acquire("locator")

	// Same arguments as Esinta: local computer, namespace, default
	// user/password/locale/authority, no flags, no context.
	sv, err := callMethod(l, loc, "ConnectServer", "", c.opts.Namespace, "", "", "", "", 0, nil)
	ci.Connect = clock.Since(t0)
	if err != nil {
		ci.Err = errInfo("ConnectServer", err)
		return
	}
	c.serviceVar = sv
	if c.service, err = sv.dispatch(); err != nil {
		ci.Err = &ErrInfo{Op: "ConnectServer", Text: err.Error()}
		return
	}

	t1 := clock.Now()
	sec, err := getProp(l, c.service, "Security_")
	if err != nil {
		ci.Err = errInfo("Security_", err)
		return
	}
	defer sec.clear()
	sd, err := sec.dispatch()
	if err != nil {
		ci.Err = &ErrInfo{Op: "Security_", Text: err.Error()}
		return
	}
	for _, p := range []struct {
		name string
		val  int
	}{{"AuthenticationLevel", authLevel}, {"ImpersonationLevel", impLevel}} {
		r, err := oleutil.PutProperty(sd, p.name, p.val)
		if err != nil {
			ci.Err = errInfo("Set"+p.name, err)
			return
		}
		own(l, r, "put:"+p.name).clear()
	}
	ci.Security = clock.Since(t1)
	return
}

// releaseCOM runs on the connection's thread.
func (c *Conn) releaseCOM() {
	if c.serviceVar != nil {
		c.serviceVar.clear() // releases the service
		c.serviceVar, c.service = nil, nil
	}
	if c.locator != nil {
		if c.connLedger.Release(c.locTok) {
			c.locator.Release()
		}
		c.locator = nil
	}
	if c.OnReleased != nil {
		c.OnReleased(c.connLedger.Outstanding(), c.connLedger.Double())
	}
}

// Close retires the connection. The release is queued on the connection's
// thread, so it runs after a call still in progress returns (the thread runs
// work one at a time); then the thread exits. Safe to call more than once.
func (c *Conn) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.thread.Submit(c.releaseCOM)
	c.thread.Stop()
}

// Query runs wql on the connection's thread and waits for it.
//
// With abandon, the caller gives up at deadline: Query returns a Result with
// StatusAbandoned at once, the call keeps running on its thread, and late is
// called (on that thread) with the full result when WMI answers. Without
// abandon, Query waits for the call however long it takes; the caller
// watches RunningSince for hangs. Cancelling ctx (arm shutdown) gives up the
// same way and returns StatusShutdown.
func (c *Conn) Query(ctx context.Context, wql string, deadline time.Duration, abandon bool, late func(Result)) Result {
	if c.closed.Load() {
		return Result{Status: StatusClosed, Start: time.Now()}
	}
	if inFlight.Add(1) > MaxInFlight {
		inFlight.Add(-1)
		return Result{Status: StatusOverloaded, Start: time.Now()}
	}
	c.queries.Add(1)
	var state atomic.Int32
	ch := make(chan Result, 1)
	start := time.Now()
	call := func() {
		c.runningSince.Store(time.Now().UnixNano())
		res := c.exec(wql)
		c.runningSince.Store(0)
		inFlight.Add(-1)
		c.objects.Add(uint64(res.RowsN))
		if state.CompareAndSwap(callPending, callDelivered) {
			ch <- res
			return
		}
		res.Status = StatusAbandoned
		if late != nil {
			late(res)
		}
	}
	if !c.thread.Submit(call) {
		inFlight.Add(-1)
		return Result{Status: StatusClosed, Start: start}
	}

	var timeout <-chan time.Time
	if abandon && deadline > 0 {
		t := time.NewTimer(deadline)
		defer t.Stop()
		timeout = t.C
	}
	giveUp := func(st Status) Result {
		if state.CompareAndSwap(callPending, callAbandoned) {
			abandoned.Add(1)
			return Result{Status: st, Start: start}
		}
		return <-ch // it returned at the same moment
	}
	select {
	case r := <-ch:
		return r
	case <-timeout:
		return giveUp(StatusAbandoned)
	case <-ctx.Done():
		return giveUp(StatusShutdown)
	}
}

// exec runs on the connection's thread: ExecQuery, strict enumeration,
// every property read through Properties_, every VARIANT accounted for.
func (c *Conn) exec(wql string) (res Result) {
	l := ledger.New()
	res.Start = time.Now()
	m0 := clock.Now()
	res.TID, res.AptType, res.AptOK = c.thread.OnThread()
	defer func() {
		if r := recover(); r != nil {
			res.Panics++
			res.Status = StatusError
			if res.Err == nil {
				res.Err = &ErrInfo{Op: "panic", Text: truncate(fmt.Sprint(r), 200)}
			}
		}
		res.Latency = clock.Since(m0)
		res.LedgerAcquired, res.LedgerOutstanding = l.Acquired(), l.Outstanding()
		res.LedgerDouble, res.LedgerLeaked = l.Double(), l.Leaked()
	}()
	if c.service == nil {
		res.Status = StatusError
		res.Err = &ErrInfo{Op: "ExecQuery", Text: "connection has no service"}
		return
	}
	rs, err := callMethod(l, c.service, "ExecQuery", wql, "WQL", wbemFlagReturnImmediately|wbemFlagForwardOnly)
	res.Exec = clock.Since(m0)
	if err != nil {
		res.Status = StatusError
		res.Err = errInfo("ExecQuery", err)
		return
	}
	defer rs.clear()
	set, err := rs.dispatch()
	if err != nil {
		res.Status = StatusError
		res.Err = &ErrInfo{Op: "ExecQuery", Text: err.Error()}
		return
	}
	res.EnumRan = true
	endHR, _, first, ei := enumerate(l, set, "Objects", func(item *owned) {
		res.RowsN++
		if row, ok := c.readObject(l, item, &res); ok {
			res.Rows = append(res.Rows, row)
		}
	})
	if !first.IsZero() {
		res.FirstRow = first.Sub(m0)
	}
	res.Enum = clock.Since(m0) - res.Exec
	res.EnumEndHR = endHR
	if ei != nil {
		res.Status = StatusError
		res.Err = ei
		return
	}
	res.Status = StatusOK
	return
}

// partial records the first non-fatal error of a query (a skipped object or
// property) in Err without changing the status. Status stays ok; the counts
// say what was lost.
func partial(res *Result, ei *ErrInfo) {
	if res.Err == nil && ei != nil {
		res.Err = ei
	}
}

// readObject reads every property of one result object. A failure is
// counted (ItemsSkipped / PropsFailed), never dropped silently.
func (c *Conn) readObject(l *ledger.Ledger, item *owned, res *Result) (Row, bool) {
	obj, err := item.dispatch()
	if err != nil {
		res.ItemsSkipped++
		partial(res, &ErrInfo{Op: "Item", Text: err.Error()})
		return nil, false
	}
	pv, err := getProp(l, obj, "Properties_")
	if err != nil {
		res.ItemsSkipped++
		partial(res, errInfo("Properties_", err))
		return nil, false
	}
	defer pv.clear()
	props, err := pv.dispatch()
	if err != nil {
		res.ItemsSkipped++
		partial(res, &ErrInfo{Op: "Properties_", Text: err.Error()})
		return nil, false
	}
	row := make(Row, 16)
	_, _, _, ei := enumerate(l, props, "Properties_", func(p *owned) {
		pd, err := p.dispatch()
		if err != nil {
			res.PropsFailed++
			partial(res, &ErrInfo{Op: "Property", Text: err.Error()})
			return
		}
		nv, err := getProp(l, pd, "Name")
		if err != nil {
			res.PropsFailed++
			partial(res, errInfo("Name", err))
			return
		}
		name := ""
		if nv.v.VT == ole.VT_BSTR {
			name = nv.v.ToString()
		}
		nv.clear()
		if name == "" {
			res.PropsFailed++
			partial(res, &ErrInfo{Op: "Name", Text: "empty property name"})
			return
		}
		vv, err := getProp(l, pd, "Value")
		if err != nil {
			res.PropsFailed++
			partial(res, errInfo("Value", err))
			row[name] = nil
			return
		}
		val, isArray, n := convert(vv.v)
		res.PropsRead++
		if isArray {
			res.ArrayProps++
			res.ArrayN += n
			if c.opts.LeakArrays {
				vv.leak() // buggy arm: re-creates the #115 leak
			} else {
				vv.clear()
			}
		} else {
			vv.clear()
		}
		row[name] = val
	})
	if ei != nil {
		res.PropsFailed++
		partial(res, ei)
	}
	return row, true
}

// ID returns the connection's ID.
func (c *Conn) ID() string { return c.id }

// Namespace returns the connection's namespace.
func (c *Conn) Namespace() string { return c.opts.Namespace }

// CreatedAt is when the connection finished connecting.
func (c *Conn) CreatedAt() time.Time { return c.createdAt }

// Queries is the number of queries submitted on the connection.
func (c *Conn) Queries() uint64 { return c.queries.Load() }

// Objects is the number of result objects the connection returned.
func (c *Conn) Objects() uint64 { return c.objects.Load() }

// TID is the OS thread ID of the connection's thread.
func (c *Conn) TID() uint32 { return c.thread.TID() }

// RunningSince is the start of the call in progress, or zero when idle.
func (c *Conn) RunningSince() time.Time {
	if ns := c.runningSince.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// run executes f on the connection's thread with its service (for
// pre-flight helpers). f must not keep COM pointers.
func (c *Conn) run(f func(l *ledger.Ledger, service *ole.IDispatch)) error {
	if c.closed.Load() {
		return errors.New("connection closed")
	}
	return c.thread.Run(func() { f(ledger.New(), c.service) })
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

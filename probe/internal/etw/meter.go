package etw

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// Count is one client's WMI operation starts in a drain interval.
type Count struct {
	ClientPID uint32
	Image     string
	Local     bool
	Self      bool
	Internal  bool // WmiPrvSE calling back into Winmgmt: WMI's own work, not a client
	Ops       uint64
	User      string // client account, from the first operation seen
	Sample    string // first operation other than Connect (Connect if that is all there was)
	SampleNS  string // namespace of Sample
}

// Drained is what the meter saw since the previous drain.
type Drained struct {
	On       bool          // provider enabled at drain time
	OnFor    time.Duration // time the provider was enabled during the interval
	Counts   []Count
	Self     uint64
	Internal uint64
	Foreign  uint64
	Lost     uint32 // cumulative lost events (session)
	Records  uint64 // cumulative records delivered to the consumer (session)
	Enabling string // last enable/disable error, if any
}

// Meter counts WMI operations by client process, duty-cycled.
type Meter struct {
	sess   *Session
	self   uint32
	on     time.Duration
	period time.Duration

	mu      sync.Mutex
	counts  map[key]*Count
	onSince time.Time
	onFor   time.Duration
	enErr   string
	exitRep bool // consumer end already reported
}

type key struct {
	pid   uint32
	local bool
}

// NewMeter starts the session. on/period set the duty cycle (on = period
// means always on). Run must be called to drive the cycle.
func NewMeter(on, period time.Duration) (*Meter, error) {
	m := &Meter{self: uint32(os.Getpid()), on: on, period: period, counts: map[key]*Count{}}
	s, err := Start(fmt.Sprintf("probe2-wmi-activity-%d", m.self), m.record)
	if err != nil {
		return nil, err
	}
	m.sess = s
	return m, nil
}

func (m *Meter) record(rec *eventRecord) {
	pid, ok := propUint32(rec, "ClientProcessId")
	if !ok {
		pid = 0
	}
	local, _ := propUint32(rec, "IsLocal")
	k := key{pid, local != 0}
	m.mu.Lock()
	c := m.counts[k]
	if c == nil {
		c = &Count{ClientPID: pid, Local: local != 0, Self: pid == m.self && local != 0}
		m.counts[k] = c
	}
	c.Ops++
	sample := !c.Self && (c.Sample == "" || c.Sample == opConnect)
	resolve := c.Image == "" && !c.Self
	m.mu.Unlock()
	if resolve {
		// Resolve now: short-lived clients (tasklist) are gone by the drain.
		img := imageOf(pid, local != 0)
		user := propString(rec, "User")
		m.mu.Lock()
		c.Image, c.User = img, user
		c.Internal = strings.EqualFold(filepath.Base(img), "WmiPrvSE.exe")
		m.mu.Unlock()
	}
	if sample {
		// Keep the first operation that says what the client wanted; most
		// clients open with an uninformative Connect.
		op := propString(rec, "Operation")
		ns := propString(rec, "NamespaceName")
		m.mu.Lock()
		if c.Sample == "" || (c.Sample == opConnect && op != opConnect) {
			c.Sample, c.SampleNS = op, ns
		}
		m.mu.Unlock()
	}
}

const opConnect = "IWbemServices::Connect"

func (m *Meter) setOn(on bool) {
	err := m.sess.Enable(on)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.enErr = err.Error()
		return
	}
	now := time.Now()
	if on && m.onSince.IsZero() {
		m.onSince = now
	} else if !on && !m.onSince.IsZero() {
		m.onFor += now.Sub(m.onSince)
		m.onSince = time.Time{}
	}
}

// Run drives the duty cycle until ctx ends: on for `on` at the start of each
// `period`.
func (m *Meter) Run(ctx context.Context) {
	m.setOn(true)
	if m.on >= m.period {
		<-ctx.Done()
		return
	}
	t := time.NewTimer(m.on)
	defer t.Stop()
	on := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if on {
			m.setOn(false)
			t.Reset(m.period - m.on)
		} else {
			m.setOn(true)
			t.Reset(m.on)
		}
		on = !on
	}
}

// Drain returns and resets the counts.
func (m *Meter) Drain() Drained {
	m.mu.Lock()
	counts := m.counts
	m.counts = map[key]*Count{}
	d := Drained{On: !m.onSince.IsZero(), OnFor: m.onFor, Enabling: m.enErr}
	if !m.onSince.IsZero() {
		now := time.Now()
		d.OnFor += now.Sub(m.onSince)
		m.onSince = now
	}
	m.onFor = 0
	m.mu.Unlock()

	for _, c := range counts {
		switch {
		case c.Self:
			d.Self += c.Ops
		case c.Internal:
			d.Internal += c.Ops
		default:
			d.Foreign += c.Ops
		}
		d.Counts = append(d.Counts, *c)
	}
	sort.Slice(d.Counts, func(i, j int) bool { return d.Counts[i].ClientPID < d.Counts[j].ClientPID })
	d.Lost, _, _ = m.sess.Lost()
	d.Records = m.sess.Events()
	if ex := m.sess.Exited(); ex != "" && !m.exitRep {
		m.exitRep = true
		d.Enabling = ex
	}
	return d
}

func imageOf(pid uint32, local bool) string {
	if !local {
		return "(remote)"
	}
	n := "?"
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
		buf := make([]uint16, windows.MAX_PATH)
		size := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
			n = windows.UTF16ToString(buf[:size])
		}
		windows.CloseHandle(h)
	}
	return n
}

// Close stops the session.
func (m *Meter) Close() error { return m.sess.Close() }

// Package sched produces the arm's fixed-rate query schedule (design §3.2).
// Each query key fires periodically at k x its production rate, with a
// seeded random phase, so the mix is the same in every hour and the run is
// reproducible. The rate never changes inside an arm.
package sched

import (
	"container/heap"
	"math/rand"
	"time"

	"wmiresearch/probe/internal/catalog"
)

// Job is one scheduled query.
type Job struct {
	Query catalog.Query
	Due   time.Time
	Seq   uint64 // per-key firing number
}

type entry struct {
	q      catalog.Query
	period time.Duration
	next   time.Time
	seq    uint64
}

type entries []*entry

func (e entries) Len() int           { return len(e) }
func (e entries) Less(i, j int) bool { return e[i].next.Before(e[j].next) }
func (e entries) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }
func (e *entries) Push(x any)        { *e = append(*e, x.(*entry)) }
func (e *entries) Pop() any          { old := *e; x := old[len(old)-1]; *e = old[:len(old)-1]; return x }
func (e entries) peek() *entry       { return e[0] }

// Schedule yields jobs in due order.
type Schedule struct {
	h entries
}

// New builds a schedule starting at start. Each key's period is
// 3600 s / (k x PerHour); its first firing is at a random phase within one
// period (seeded).
func New(qs []catalog.Query, k float64, start time.Time, seed int64) *Schedule {
	rng := rand.New(rand.NewSource(seed))
	s := &Schedule{}
	for _, q := range qs {
		rate := k * q.PerHour
		if rate <= 0 {
			continue
		}
		period := time.Duration(float64(time.Hour) / rate)
		phase := time.Duration(rng.Int63n(int64(period) + 1))
		s.h = append(s.h, &entry{q: q, period: period, next: start.Add(phase)})
	}
	heap.Init(&s.h)
	return s
}

// Empty reports whether the schedule has no queries.
func (s *Schedule) Empty() bool { return len(s.h) == 0 }

// Next returns the next job and advances that key by one period. Due times
// are computed from the start, not from when the previous job ran, so a
// slow consumer does not change the rate.
func (s *Schedule) Next() Job {
	e := s.h.peek()
	j := Job{Query: e.q, Due: e.next, Seq: e.seq}
	e.seq++
	e.next = e.next.Add(e.period)
	heap.Fix(&s.h, 0)
	return j
}

// PeekDue is the due time of the next job.
func (s *Schedule) PeekDue() time.Time { return s.h.peek().next }

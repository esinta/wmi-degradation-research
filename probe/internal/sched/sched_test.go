package sched

import (
	"math"
	"testing"
	"time"

	"wmiresearch/probe/internal/catalog"
)

func TestRatesAndOrder(t *testing.T) {
	qs := catalog.Production()
	start := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	const k = 50.0
	s := New(qs, k, start, 1)
	end := start.Add(time.Hour)
	counts := map[string]int{}
	prev := start
	for s.PeekDue().Before(end) {
		j := s.Next()
		if j.Due.Before(prev) {
			t.Fatalf("out of order: %v after %v", j.Due, prev)
		}
		prev = j.Due
		counts[j.Query.Key]++
	}
	for _, q := range qs {
		want := k * q.PerHour
		if got := float64(counts[q.Key]); math.Abs(got-want) > 1 {
			t.Errorf("%s: %g in 1 h, want %g", q.Key, got, want)
		}
	}
}

func TestSeedIsReproducible(t *testing.T) {
	qs := catalog.Production()
	start := time.Now()
	a, b := New(qs, 5, start, 42), New(qs, 5, start, 42)
	for range 1000 {
		ja, jb := a.Next(), b.Next()
		if ja.Query.Key != jb.Query.Key || !ja.Due.Equal(jb.Due) {
			t.Fatal("same seed, different schedule")
		}
	}
}

func TestZeroRateSkipped(t *testing.T) {
	s := New([]catalog.Query{{Key: "x", PerHour: 0}}, 10, time.Now(), 1)
	if !s.Empty() {
		t.Fatal("zero-rate query scheduled")
	}
}

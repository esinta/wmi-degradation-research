package strategy

import (
	"testing"
	"time"

	"wmiresearch/probe/internal/hresult"
)

var t0 = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

func TestNoneNeverReplaces(t *testing.T) {
	c, _ := Parse("none", 0)
	if r, _ := c.Before(t0.Add(1000*time.Hour), ConnState{Created: t0, Queries: 1e9}); r {
		t.Fatal("none replaced before")
	}
	if r, _ := c.After(Outcome{Abandoned: true, Errored: true, HR: hresult.RPCSServerUnavail}); r {
		t.Fatal("none replaced after")
	}
	if c.Abandons() {
		t.Fatal("none abandons")
	}
}

func TestTimed(t *testing.T) {
	if _, err := Parse("timed", 0); err == nil {
		t.Fatal("timed without interval accepted")
	}
	c, _ := Parse("timed", time.Hour)
	if r, _ := c.Before(t0.Add(59*time.Minute), ConnState{Created: t0}); r {
		t.Fatal("early")
	}
	if r, why := c.Before(t0.Add(time.Hour), ConnState{Created: t0}); !r || why != "timed" {
		t.Fatal("not at interval")
	}
}

func TestAdaptive(t *testing.T) {
	c, _ := Parse("adaptive", 0)
	cases := []struct {
		o    Outcome
		want bool
	}{
		{Outcome{Abandoned: true}, true},
		{Outcome{Errored: true, HR: hresult.DispEException, SCode: hresult.WBEMETransportFailure}, true},
		{Outcome{Errored: true, HR: hresult.RPCSServerUnavail}, true},
		{Outcome{Errored: true, HR: hresult.DispEException, SCode: hresult.WBEMEInvalidClass}, false},
		{Outcome{ImpossibleEmpty: true}, true},
		{Outcome{}, false},
	}
	for i, tc := range cases {
		if r, why := c.After(tc.o); r != tc.want {
			t.Errorf("case %d: %v (%s)", i, r, why)
		}
	}
	if !c.Abandons() {
		t.Fatal("adaptive must abandon at deadline")
	}
}

func TestPoolMatchesEsinta(t *testing.T) {
	c, _ := Parse("pool", 0)
	now := t0.Add(time.Hour)
	if r, _ := c.Before(now, ConnState{Created: t0, LastUsed: now, Queries: PoolMaxQueries}); r {
		t.Fatal("recycled at exactly 50k (Esinta uses >)")
	}
	if r, why := c.Before(now, ConnState{Created: t0, LastUsed: now, Queries: PoolMaxQueries + 1}); !r || why != "count" {
		t.Fatal("count")
	}
	if r, why := c.Before(t0.Add(6*time.Hour+time.Second), ConnState{Created: t0, LastUsed: now}); !r || why != "age" {
		t.Fatal("age")
	}
	if r, why := c.Before(now, ConnState{Created: t0, LastUsed: now.Add(-6 * time.Minute)}); !r || why != "idle" {
		t.Fatal("idle")
	}
	// Esinta maps the outer HRESULT: a wrapped transport failure is not unhealthy.
	if r, _ := c.After(Outcome{Errored: true, HR: hresult.DispEException, SCode: hresult.WBEMETransportFailure}); r {
		t.Fatal("wrapped error replaced")
	}
	if r, _ := c.After(Outcome{Abandoned: true}); !r {
		t.Fatal("abandoned not replaced")
	}
}

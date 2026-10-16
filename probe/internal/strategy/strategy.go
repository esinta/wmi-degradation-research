// Package strategy decides when a connection is replaced (design §4.1, arms
// E0-E3). Decisions are pure functions of the connection's state and the
// last query's outcome, so they are the same in every arm and testable.
package strategy

import (
	"fmt"
	"time"

	"wmiresearch/probe/internal/hresult"
)

// Kind is a refresh strategy.
type Kind string

const (
	None     Kind = "none"     // E0 / all rate arms: never replace
	Timed    Kind = "timed"    // E1: replace at a fixed connection age
	Adaptive Kind = "adaptive" // E2: replace on a connection-level error, an abandoned call or an impossible empty
	Pool     Kind = "pool"     // E3: Esinta's production pool semantics
)

// Esinta pool constants (internal/agent/wmi: getMaxAge, getMaxQueries,
// DefaultMaxIdleTime).
const (
	PoolMaxAge     = 6 * time.Hour
	PoolMaxQueries = 50000
	PoolMaxIdle    = 5 * time.Minute
)

// Config is one arm's strategy.
type Config struct {
	Kind          Kind
	TimedInterval time.Duration // Timed only
}

// Parse builds a Config.
func Parse(kind string, timed time.Duration) (Config, error) {
	c := Config{Kind: Kind(kind), TimedInterval: timed}
	switch c.Kind {
	case None, Adaptive, Pool:
	case Timed:
		if timed <= 0 {
			return c, fmt.Errorf("timed strategy needs a positive interval")
		}
	default:
		return c, fmt.Errorf("unknown strategy %q (none | timed | adaptive | pool)", kind)
	}
	return c, nil
}

// Abandons reports whether calls are abandoned at their deadline. Esinta's
// pool does; so does the adaptive arm (a timeout is one of its triggers).
// none and timed wait for every call, so their latency tail is complete.
func (c Config) Abandons() bool { return c.Kind == Adaptive || c.Kind == Pool }

// ConnState is what a strategy may look at.
type ConnState struct {
	Created  time.Time
	LastUsed time.Time
	Queries  uint64
}

// Before is checked before a query: replace the connection first?
//
// The pool arm checks age and count here, at the moment the connection is
// idle, like Esinta's checkAndRecycleConnections; Esinta's 30 s health
// check could recycle an idle connection up to one health interval earlier,
// which differs only for connections idle at that moment.
func (c Config) Before(now time.Time, st ConnState) (replace bool, reason string) {
	switch c.Kind {
	case Timed:
		if now.Sub(st.Created) >= c.TimedInterval {
			return true, "timed"
		}
	case Pool:
		switch {
		case now.Sub(st.Created) > PoolMaxAge:
			return true, "age"
		case st.Queries > PoolMaxQueries:
			return true, "count"
		case !st.LastUsed.IsZero() && now.Sub(st.LastUsed) > PoolMaxIdle:
			return true, "idle"
		}
	}
	return false, ""
}

// Outcome is what a strategy may look at after a query.
type Outcome struct {
	Abandoned       bool
	Errored         bool
	HR, SCode       uint32
	ImpossibleEmpty bool // ok status but 0 rows from a class that cannot be empty
}

// After is checked after a query: replace the connection now?
func (c Config) After(o Outcome) (replace bool, reason string) {
	switch c.Kind {
	case Adaptive:
		switch {
		case o.Abandoned:
			return true, "adaptive:timeout"
		case o.Errored && hresult.ConnectionLevel(hresult.Effective(o.HR, o.SCode)):
			return true, "adaptive:" + hresult.Name(hresult.Effective(o.HR, o.SCode))
		case o.ImpossibleEmpty:
			return true, "adaptive:impossible_empty"
		}
	case Pool:
		switch {
		case o.Abandoned:
			return true, "abandoned"
		case o.Errored && hresult.EsintaUnhealthy(o.HR):
			return true, "unhealthy"
		}
	}
	return false, ""
}

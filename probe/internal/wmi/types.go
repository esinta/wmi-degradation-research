// Package wmi is the probe's WMI client: correct by construction (design §2).
//
// Patterns copied from Esinta's internal/agent/wmi (read, not imported): one
// STA thread per connection (package sta), every COM call on the
// connection's objects made on that thread, every VARIANT cleared once
// (arrays included), the release on the owning thread, semisynchronous
// forward-only ExecQuery, properties read through Properties_.
//
// Deliberate deviations (design §2.2): no oleutil.ForEach (it ends silently
// when IEnumVARIANT::Next fails with zero items), no silent skipping of
// objects or properties, no silent panic recovery, and full error capture
// including the EXCEPINFO scode.
package wmi

import (
	"time"
)

// Status is the outcome of one query.
type Status string

const (
	StatusOK         Status = "ok"
	StatusError      Status = "error"
	StatusAbandoned  Status = "abandoned"  // caller gave up at the deadline; row written when the call returns
	StatusOverloaded Status = "overloaded" // in-flight cap reached; no call made
	StatusClosed     Status = "closed"     // connection already closed; no call made
	StatusNoConn     Status = "noconn"     // no connection (connect failing); no call made
	StatusShutdown   Status = "shutdown"   // arm ended while the call was running
)

// ErrInfo is a fully captured COM/WMI error.
type ErrInfo struct {
	Op    string // ExecQuery, _NewEnum, Next, Properties_, Properties_.Next, Name, Value, Connect, ...
	HR    uint32 // outer HRESULT
	SCode uint32 // EXCEPINFO scode (the WBEM code when HR is DISP_E_EXCEPTION)
	WCode uint16
	Src   string
	Text  string
}

// Row is one result object, converted to Go values (no COM pointers).
type Row map[string]any

// Result is everything recorded about one query (design §6.2).
type Result struct {
	Status Status
	Start  time.Time
	// Latency is the full call time; Exec is ExecQuery's return, FirstRow the
	// first Next, Enum the whole enumeration (including property reads).
	Latency, Exec, FirstRow, Enum time.Duration

	Rows                                 []Row
	RowsN, PropsRead, ArrayProps, ArrayN int

	Err       *ErrInfo
	EnumRan   bool   // the object enumeration started (ExecQuery returned a set)
	EnumEndHR uint32 // HRESULT that ended the object enumeration (S_FALSE expected)

	ItemsSkipped, PropsFailed, Panics int

	TID     uint32
	AptType int
	AptOK   bool

	LedgerAcquired, LedgerOutstanding, LedgerDouble, LedgerLeaked int
}

// ConnectInfo describes how a connection was established.
type ConnectInfo struct {
	STAStart, Connect, Security time.Duration
	Err                         *ErrInfo
}

// Options configure a connection.
type Options struct {
	Namespace string
	// ConnectTimeout bounds STA start + ConnectServer + security setup.
	ConnectTimeout time.Duration
	// Buggy behaviours, only for client class "buggy" (design §4.1).
	LeakArrays     bool // B1 / ST-2: do not VariantClear array values (re-creates #115)
	CrossApartment bool // B2: MTA thread, objects land in the host STA (re-creates pre-#118)
}

// MaxInFlight bounds COM calls running at once across all connections, as
// in Esinta (maxInFlightWMICalls).
const MaxInFlight = 16

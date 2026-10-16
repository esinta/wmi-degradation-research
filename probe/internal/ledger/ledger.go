// Package ledger proves, per query, that every COM reference the client
// acquired was released exactly once (design §2.3). The wmi package registers
// each VARIANT it gets back (property values, method results, enumerator
// items) and each interface it obtains with an AddRef (QueryInterface), and
// checks them off when it clears or releases them.
//
// A Ledger belongs to one query on one STA thread; it is not safe for
// concurrent use and needs no lock.
package ledger

// Ledger counts acquisitions and releases.
type Ledger struct {
	next        uint64
	open        map[uint64]string
	double      int
	leaked      int // released deliberately without freeing (buggy arm B1/ST-2)
	acquired    int
	maxOpen     int
	doubleKinds map[string]int
}

// New returns an empty ledger.
func New() *Ledger {
	return &Ledger{open: make(map[uint64]string, 64)}
}

// Acquire registers one reference of the given kind and returns its token.
func (l *Ledger) Acquire(kind string) uint64 {
	l.next++
	l.open[l.next] = kind
	l.acquired++
	if len(l.open) > l.maxOpen {
		l.maxOpen = len(l.open)
	}
	return l.next
}

// Release checks a token off. It reports false, and counts a double release,
// when the token is not open: the caller must then not free the object again.
func (l *Ledger) Release(tok uint64) bool {
	kind, ok := l.open[tok]
	if !ok {
		l.double++
		if l.doubleKinds == nil {
			l.doubleKinds = map[string]int{}
		}
		l.doubleKinds[kind]++
		return false
	}
	delete(l.open, tok)
	return true
}

// Leak records a reference that is deliberately left unfreed. The token stays
// open, so Outstanding counts it: a buggy arm's leak is visible in its rows.
func (l *Ledger) Leak(tok uint64) {
	if _, ok := l.open[tok]; ok {
		l.leaked++
	}
}

// Outstanding is the number of references not released.
func (l *Ledger) Outstanding() int { return len(l.open) }

// Double is the number of releases of a reference that was not open.
func (l *Ledger) Double() int { return l.double }

// Leaked is the number of references deliberately left unfreed.
func (l *Ledger) Leaked() int { return l.leaked }

// Acquired is the total number of references registered.
func (l *Ledger) Acquired() int { return l.acquired }

// OpenKinds summarizes the outstanding references by kind (for debugging a
// non-zero Outstanding).
func (l *Ledger) OpenKinds() map[string]int {
	m := map[string]int{}
	for _, k := range l.open {
		m[k]++
	}
	return m
}

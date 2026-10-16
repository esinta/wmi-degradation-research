// Package sta runs a WMI connection's COM calls on one dedicated OS thread.
//
// The pattern is copied from Esinta's internal/agent/wmi/sta_thread.go (read,
// not imported). The WMI scripting objects (wbemdisp: SWbemLocator and all it
// returns) are ThreadingModel=Apartment. Created and used on their own STA
// thread, every call is direct. Created from an MTA thread, COM puts them in
// the process's host STA and marshals every call into it: the pre-#118
// pattern (~3x CPU per query, all WMI work serialized behind one thread).
//
// ModeMTA exists only to reproduce that bug in the labeled buggy arm B2.
package sta

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

// Mode is the apartment a thread joins.
type Mode int

const (
	ModeSTA Mode = iota // correct client
	ModeMTA             // buggy arm B2 only: wbemdisp objects end up in the host STA
)

// APTTYPE values from CoGetApartmentType.
const (
	AptCurrent = -1
	AptSTA     = 0
	AptMTA     = 1
	AptNA      = 2
	AptMainSTA = 3
)

// backlog bounds queued work: a connection runs one call at a time, plus its
// release; more is a caller bug.
const backlog = 4

// ErrStopped is returned when work is submitted to a stopped thread.
var ErrStopped = errors.New("connection thread stopped")

// Thread executes functions on one locked OS thread.
type Thread struct {
	mu     sync.Mutex
	work   chan func()
	closed bool
	done   chan struct{}
	tid    uint32
	mode   Mode
}

var (
	anchorOnce sync.Once
	anchorErr  error
)

// startAnchor keeps one STA alive for the life of the process. COM registers
// the hidden window class every STA needs (OleMainThreadWndClass) with the
// first STA and unregisters it when the last one uninitializes; a thread
// starting while another's CoUninitialize unregisters it fails with "Cannot
// find window class" (seen in Esinta on back-to-back recycles).
func startAnchor() error {
	anchorOnce.Do(func() {
		ready := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil && !alreadyInitialized(err) {
				ready <- fmt.Errorf("COM initialization (anchor STA): %w", err)
				return
			}
			ready <- nil
			select {} // hold the apartment for the life of the process
		}()
		anchorErr = <-ready
	})
	return anchorErr
}

// New starts a thread in the given mode and initializes COM on it.
func New(mode Mode) (*Thread, error) {
	if err := startAnchor(); err != nil {
		return nil, err
	}
	t := &Thread{work: make(chan func(), backlog), done: make(chan struct{}), mode: mode}
	ready := make(chan error, 1)
	go t.loop(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Thread) loop(ready chan<- error) {
	defer close(t.done)
	// Never unlocked: when this goroutine returns, Go terminates the OS
	// thread, and the apartment and anything COM cached on it go with it.
	runtime.LockOSThread()
	coinit := uint32(ole.COINIT_APARTMENTTHREADED)
	if t.mode == ModeMTA {
		coinit = ole.COINIT_MULTITHREADED
	}
	if err := ole.CoInitializeEx(0, coinit); err != nil && !alreadyInitialized(err) {
		ready <- fmt.Errorf("COM initialization: %w", err)
		return
	}
	t.tid = windows.GetCurrentThreadId()
	ready <- nil
	for f := range t.work {
		f() // callers recover their own panics and record them
	}
	ole.CoUninitialize()
}

// TID is the OS thread ID of the thread.
func (t *Thread) TID() uint32 { return t.tid }

// Mode is the apartment mode the thread was started in.
func (t *Thread) Mode() Mode { return t.mode }

// Submit queues f without blocking. It reports false when the thread was
// stopped or the backlog is full.
func (t *Thread) Submit(f func()) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	select {
	case t.work <- f:
		return true
	default:
		return false
	}
}

// Run executes f on the thread and waits for it. Never call it from the
// thread itself.
func (t *Thread) Run(f func()) error {
	done := make(chan struct{})
	if !t.Submit(func() {
		defer close(done)
		f()
	}) {
		return ErrStopped
	}
	<-done
	return nil
}

// Stop lets the thread finish the work already queued, then uninitialize COM
// and exit. Safe to call more than once.
func (t *Thread) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.work)
	}
}

// Done is closed when the thread has exited.
func (t *Thread) Done() <-chan struct{} { return t.done }

var procCoGetApartmentType = windows.NewLazySystemDLL("ole32.dll").NewProc("CoGetApartmentType")

// ApartmentType returns the calling thread's APTTYPE, or AptCurrent on error.
func ApartmentType() int {
	var typ, qual int32
	hr, _, _ := procCoGetApartmentType.Call(uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&qual)))
	if hr != 0 {
		return AptCurrent
	}
	return int(typ)
}

// OnThread reports whether the caller runs on t's thread in a single-threaded
// apartment: the correct-client invariant (design §2.3).
func (t *Thread) OnThread() (tid uint32, apt int, ok bool) {
	tid = windows.GetCurrentThreadId()
	apt = ApartmentType()
	ok = tid == t.tid && (apt == AptSTA || apt == AptMainSTA)
	return
}

func alreadyInitialized(err error) bool {
	if err == nil {
		return false
	}
	var oe *ole.OleError
	if errors.As(err, &oe) && oe.Code() == 1 { // S_FALSE
		return true
	}
	return strings.Contains(err.Error(), "0x00000001")
}

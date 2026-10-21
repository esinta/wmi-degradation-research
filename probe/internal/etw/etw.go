// Package etw is the foreign-WMI-client meter (design §7): a real-time ETW
// session on Microsoft-Windows-WMI-Activity that counts WMI operations
// (event 11, "operation start") by ClientProcessId. It uses no WMI.
//
// The session stays open for the whole run; the provider is enabled and
// disabled to duty-cycle it (tracing every one of the probe's own operations
// costs Winmgmt some CPU).
package etw

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WMIActivity is Microsoft-Windows-WMI-Activity.
var WMIActivity = windows.GUID{Data1: 0x1418EF04, Data2: 0xB0B4, Data3: 0x4623, Data4: [8]byte{0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA}}

const evOperationStart = 11

var (
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	tdh                    = windows.NewLazySystemDLL("tdh.dll")
	procStartTraceW        = advapi32.NewProc("StartTraceW")
	procControlTraceW      = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2     = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW         = advapi32.NewProc("OpenTraceW")
	procProcessTrace       = advapi32.NewProc("ProcessTrace")
	procCloseTrace         = advapi32.NewProc("CloseTrace")
	procTdhGetProperty     = tdh.NewProc("TdhGetProperty")
	procTdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
)

const (
	wnodeFlagTracedGUID     = 0x00020000
	eventTraceRealTimeMode  = 0x00000100
	controlQuery            = 0
	controlStop             = 1
	enableProvider          = 1
	disableProvider         = 0
	processTraceRealTime    = 0x00000100
	processTraceEventRecord = 0x10000000
	levelVerbose            = 5
	// keywordTrace selects the provider's Trace channel, which carries event
	// 11. Enabling all keywords also selects the Debug channel (event 100,
	// level 0, so the level does not filter it), which on Windows 11
	// 26200.9457+ fires ~170 times per operation. That volume was handled
	// (pre-flight ramp, k=100, 0 lost); the battery 3 losses came from an
	// orphaned session (see Start). This only cuts the meter's load.
	keywordTrace       = 0x8000000000000000
	invalidTraceHandle = ^uint64(0)
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties is EVENT_TRACE_PROPERTIES (120 bytes on amd64).
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW (448 bytes on amd64); the parts
// the consumer never reads are opaque.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte
	LogfileHeader       [280]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      windows.GUID
}

// eventRecord is EVENT_RECORD (112 bytes on amd64).
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type propertyDataDescriptor struct {
	PropertyName uintptr
	ArrayIndex   uint32
	Reserved     uint32
}

// Op is one WMI operation start seen by the session.
type Op struct {
	ClientPID uint32
	IsLocal   bool
	Operation string // filled only when the Meter asks for it
}

// Session is one real-time ETW session on WMI-Activity.
type Session struct {
	name    string
	handle  uint64 // session (TRACEHANDLE from StartTrace)
	trace   uint64 // consumer (from OpenTrace)
	props   []byte
	enabled bool
	mu      sync.Mutex
	onOp    func(rec *eventRecord)
	done    chan error
	events  atomic.Uint64 // every record delivered, any provider or ID
	exited  atomic.Value  // string: when and how ProcessTrace returned
}

// active maps the callback's UserContext to its session (callbacks are
// plain C function pointers, so the Go side is found by key).
var (
	activeMu sync.Mutex
	active   = map[uintptr]*Session{}
	nextKey  uintptr
	callback = syscall.NewCallback(eventCallback)
)

func eventCallback(rec *eventRecord) uintptr {
	activeMu.Lock()
	s := active[rec.UserContext]
	activeMu.Unlock()
	if s != nil {
		s.events.Add(1)
	}
	if s != nil && rec.EventHeader.ProviderID == WMIActivity && rec.EventHeader.EventDescriptor.ID == evOperationStart {
		s.onOp(rec)
	}
	return 0
}

func newProps(name string) ([]byte, *eventTraceProperties) {
	n, _ := windows.UTF16FromString(name)
	size := int(unsafe.Sizeof(eventTraceProperties{})) + 2*len(n) + 2*1024
	buf := make([]byte, size)
	p := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	p.Wnode.BufferSize = uint32(size)
	p.Wnode.Flags = wnodeFlagTracedGUID
	p.Wnode.ClientContext = 1 // QPC timestamps
	p.LogFileMode = eventTraceRealTimeMode
	p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	p.FlushTimer = 1
	return buf, p
}

func control(name string, code uint32) (*eventTraceProperties, error) {
	buf, p := newProps(name)
	n, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procControlTraceW.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(p)), uintptr(code))
	runtime.KeepAlive(buf)
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return p, nil
}

// Start opens a real-time session named name (a stale session of the same
// name, from a crashed run, is stopped first) and starts consuming it. The
// provider is not enabled until Enable.
//
// A session outlives its process: killing a probe2 without Close leaves a
// session with the provider enabled and no consumer. On the Win11 host one
// such session (2026-10-20) made every later WMI-Activity session lose all
// its events under load until it was stopped. Before a run, check with
// `logman query -ets | findstr probe2` and stop any session whose PID is gone.
func Start(name string, onOp func(rec *eventRecord)) (*Session, error) {
	s := &Session{name: name, onOp: onOp, done: make(chan error, 1)}
	buf, p := newProps(name)
	n, _ := windows.UTF16PtrFromString(name)
	var h uint64
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(p)))
	if syscall.Errno(r) == windows.ERROR_ALREADY_EXISTS {
		_, _ = control(name, controlStop)
		buf, p = newProps(name)
		r, _, _ = procStartTraceW.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(p)))
	}
	if r != 0 {
		return nil, fmt.Errorf("StartTrace %s: %w", name, syscall.Errno(r))
	}
	s.handle, s.props = h, buf

	activeMu.Lock()
	nextKey++
	key := nextKey
	active[key] = s
	activeMu.Unlock()

	lf := &eventTraceLogfile{LoggerName: n, ProcessTraceMode: processTraceRealTime | processTraceEventRecord,
		EventRecordCallback: callback, Context: key}
	t, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	if uint64(t) == invalidTraceHandle {
		s.stopSession()
		return nil, fmt.Errorf("OpenTrace %s: %v", name, err)
	}
	s.trace = uint64(t)
	go func() {
		runtime.LockOSThread()
		r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&s.trace)), 1, 0, 0)
		// Record the consumer's end: if it ends before Close, the session
		// keeps running and every later event is lost without an error.
		s.exited.Store(fmt.Sprintf("ProcessTrace returned at %s: %v (%d records)",
			time.Now().UTC().Format(time.RFC3339), syscall.Errno(r), s.events.Load()))
		if r != 0 && syscall.Errno(r) != windows.ERROR_CANCELLED {
			s.done <- syscall.Errno(r)
			return
		}
		s.done <- nil
	}()
	return s, nil
}

// Enable turns the WMI-Activity provider on or off for this session.
func (s *Session) Enable(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on == s.enabled {
		return nil
	}
	code := uintptr(disableProvider)
	if on {
		code = enableProvider
	}
	g := WMIActivity
	r, _, _ := procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&g)), code, levelVerbose,
		keywordTrace, 0, 0, 0)
	if r != 0 {
		return fmt.Errorf("EnableTraceEx2(%v): %w", on, syscall.Errno(r))
	}
	s.enabled = on
	return nil
}

// Lost is the session's lost-event and lost-buffer count so far.
func (s *Session) Lost() (events, buffers uint32, err error) {
	p, err := control(s.name, controlQuery)
	if err != nil {
		return 0, 0, err
	}
	return p.EventsLost, p.RealTimeBuffersLost + p.LogBuffersLost, nil
}

// Events is the number of records delivered to this session's consumer.
func (s *Session) Events() uint64 { return s.events.Load() }

// Exited says when and how the consumer ended, or "" while it runs.
func (s *Session) Exited() string {
	v, _ := s.exited.Load().(string)
	return v
}

func (s *Session) stopSession() {
	_, _ = control(s.name, controlStop)
}

// Close disables the provider, stops the session and waits for the consumer.
func (s *Session) Close() error {
	_ = s.Enable(false)
	s.stopSession()
	if s.trace != 0 {
		procCloseTrace.Call(uintptr(s.trace))
	}
	var err error
	select {
	case err = <-s.done:
	case <-time.After(10 * time.Second):
		err = errors.New("ProcessTrace did not return")
	}
	activeMu.Lock()
	for k, v := range active {
		if v == s {
			delete(active, k)
		}
	}
	activeMu.Unlock()
	return err
}

// propUint32 reads a 4-byte property (UINT32 or BOOL) by name.
func propUint32(rec *eventRecord, name string) (uint32, bool) {
	n, _ := windows.UTF16PtrFromString(name)
	d := propertyDataDescriptor{PropertyName: uintptr(unsafe.Pointer(n)), ArrayIndex: ^uint32(0)}
	var v uint32
	r, _, _ := procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), 4, uintptr(unsafe.Pointer(&v)))
	return v, r == 0
}

// propString reads a UTF-16 string property by name.
func propString(rec *eventRecord, name string) string {
	n, _ := windows.UTF16PtrFromString(name)
	d := propertyDataDescriptor{PropertyName: uintptr(unsafe.Pointer(n)), ArrayIndex: ^uint32(0)}
	var size uint32
	if r, _, _ := procTdhGetPropertySize.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&size))); r != 0 || size < 2 {
		return ""
	}
	buf := make([]uint16, (size+1)/2)
	if r, _, _ := procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(size), uintptr(unsafe.Pointer(&buf[0]))); r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

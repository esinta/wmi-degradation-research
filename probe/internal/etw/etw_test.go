package etw

import (
	"testing"
	"unsafe"
)

// The hand-written layouts must match the Windows SDK sizes on amd64.
func TestLayouts(t *testing.T) {
	for name, got := range map[string]uintptr{
		"EVENT_TRACE_PROPERTIES": unsafe.Sizeof(eventTraceProperties{}),
		"EVENT_TRACE_LOGFILEW":   unsafe.Sizeof(eventTraceLogfile{}),
		"EVENT_RECORD":           unsafe.Sizeof(eventRecord{}),
		"EVENT_HEADER":           unsafe.Sizeof(eventHeader{}),
		"WNODE_HEADER":           unsafe.Sizeof(wnodeHeader{}),
	} {
		want := map[string]uintptr{"EVENT_TRACE_PROPERTIES": 120, "EVENT_TRACE_LOGFILEW": 448, "EVENT_RECORD": 112, "EVENT_HEADER": 80, "WNODE_HEADER": 48}[name]
		if got != want {
			t.Errorf("%s: %d bytes, want %d", name, got, want)
		}
	}
	if off := unsafe.Offsetof(eventTraceLogfile{}.EventRecordCallback); off != 424 {
		t.Errorf("EventRecordCallback at %d, want 424", off)
	}
	if off := unsafe.Offsetof(eventTraceLogfile{}.Context); off != 440 {
		t.Errorf("Context at %d, want 440", off)
	}
	if off := unsafe.Offsetof(eventRecord{}.UserContext); off != 104 {
		t.Errorf("UserContext at %d, want 104", off)
	}
}

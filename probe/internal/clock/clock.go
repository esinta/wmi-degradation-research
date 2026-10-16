// Package clock times durations with QueryPerformanceCounter.
//
// Go's monotonic clock on Windows advances in ~0.5 ms steps on the dev
// laptop (measured 2026-10-16), and can be as coarse as the 15.6 ms timer
// tick on other hosts. Query latencies are 14-20 ms at the median, so every
// duration the probe records comes from QPC instead.
package clock

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	k32      = windows.NewLazySystemDLL("kernel32.dll")
	procQPC  = k32.NewProc("QueryPerformanceCounter")
	procFreq = k32.NewProc("QueryPerformanceFrequency")
	freq     int64
)

func init() {
	procFreq.Call(uintptr(unsafe.Pointer(&freq)))
	if freq <= 0 {
		freq = 1 // never happens on XP and later; keeps Since from dividing by 0
	}
}

// Mark is a QPC reading.
type Mark int64

// Now reads the counter.
func Now() Mark {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	return Mark(c)
}

// Sub is the duration from b to m.
func (m Mark) Sub(b Mark) time.Duration {
	d := int64(m - b)
	return time.Duration(d/freq)*time.Second + time.Duration(d%freq)*time.Second/time.Duration(freq)
}

// Since is the duration from m to now.
func Since(m Mark) time.Duration { return Now().Sub(m) }

// IsZero reports an unset mark.
func (m Mark) IsZero() bool { return m == 0 }

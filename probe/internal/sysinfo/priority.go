package sysinfo

import (
	"fmt"

	"golang.org/x/sys/windows"
)

var priorityNames = map[uint32]string{
	windows.IDLE_PRIORITY_CLASS:         "idle",
	windows.BELOW_NORMAL_PRIORITY_CLASS: "below_normal",
	windows.NORMAL_PRIORITY_CLASS:       "normal",
	windows.ABOVE_NORMAL_PRIORITY_CLASS: "above_normal",
	windows.HIGH_PRIORITY_CLASS:         "high",
	windows.REALTIME_PRIORITY_CLASS:     "realtime",
}

// PriorityName names a process priority class.
func PriorityName(c uint32) string {
	if n, ok := priorityNames[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%x", c)
}

// NormalPriority puts this process in NORMAL_PRIORITY_CLASS, like a service
// (Esinta runs as one). Task Scheduler starts tasks below normal by default
// (task priority 7), which would bias probe-side latency under contention.
// It returns "<before>" or "<before>->normal".
func NormalPriority() (string, error) {
	h := windows.CurrentProcess()
	c, err := windows.GetPriorityClass(h)
	if err != nil {
		return "", err
	}
	if c == windows.NORMAL_PRIORITY_CLASS {
		return PriorityName(c), nil
	}
	if err := windows.SetPriorityClass(h, windows.NORMAL_PRIORITY_CLASS); err != nil {
		return PriorityName(c), err
	}
	return PriorityName(c) + "->normal", nil
}

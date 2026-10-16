// Package catalog holds the probe's query catalog: Esinta's own WQL, at the
// per-hour rates measured from the Win10 lab VM's audit logs (design §1,
// §3.1). Every arm multiplies these rates by one factor k (§3.2), so the
// accelerated workload keeps the production mix.
package catalog

import (
	"fmt"
	"sort"
	"strings"
)

// Namespaces used by the catalog.
const (
	NSCimv2         = `root\cimv2`
	NSStandardCimv2 = `root\StandardCimv2`
	NSDefender      = `root\Microsoft\Windows\Defender`
	NSSubscription  = `root\subscription`
	NSTaskScheduler = `root\Microsoft\Windows\TaskScheduler`
	NSDeviceGuard   = `root\Microsoft\Windows\DeviceGuard`
	NSVolumeEncrypt = `root\CIMV2\Security\MicrosoftVolumeEncryption`
	NSTpm           = `root\CIMV2\Security\MicrosoftTpm`
)

// Truth says how a query's result is checked against a non-WMI source
// (design §6.6).
type Truth int

const (
	TruthNone       Truth = iota // no check (e.g. event-log queries; empty is normal)
	TruthPID                     // proc_pid: bracketed OpenProcess check of the target PID
	TruthProcSet                 // bracketed NtQuerySystemInformation process set
	TruthServices                // bracketed SCM Win32 service names
	TruthDrivers                 // bracketed SCM driver names
	TruthKeySet                  // invariant: set of KeyProp values equals the run's t0 set
	TruthExactlyOne              // exactly one row, always
	TruthCount                   // invariant: row count equals the run's t0 count
)

func (t Truth) String() string {
	return [...]string{"none", "pid", "procset", "services", "drivers", "keyset", "exactly1", "count"}[t]
}

// Query is one catalog entry.
type Query struct {
	Key       string
	Namespace string
	// WQL is the query text. proc_pid has one %d (the target PID); the
	// event-log queries have one %s (a CIM datetime, now - 2 min).
	WQL     string
	PerHour float64 // rate at k = 1
	// Class is the WMI class, for provider-host attribution.
	Class string
	// Repository marks classes served by Winmgmt from the CIM repository
	// (no provider host).
	Repository bool
	Truth      Truth
	// KeyProp is the property compared for TruthProcSet/Services/Drivers/KeySet.
	KeyProp string
	// Registry names a registry count that cross-checks an invariant
	// ("fwrules", "tasks"); empty for none.
	Registry string
	// Composite says whether the query belongs to the primary latency
	// composite P1 (design §5.2). Event-log queries are excluded: their cost
	// grows with log size (threat T10).
	Composite bool
	// ImpossibleEmpty: 0 rows can never be a correct answer (silent class
	// S1, and the adaptive strategy's trigger).
	ImpossibleEmpty bool
}

// Production returns the production-shaped catalog (design §3.1). Rates are
// per hour at k = 1 and sum per namespace to the measured Esinta rates:
// cimv2 420, subscription 60, Defender 60, StandardCimv2 48, TaskScheduler
// 24, each host-posture namespace 12.
func Production() []Query {
	const procCols = "ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, " +
		"WorkingSetSize, VirtualSize, HandleCount, ThreadCount, SessionId, Priority"
	const evtFmt = "SELECT RecordNumber, TimeGenerated, EventCode, Logfile, SourceName, User, InsertionStrings " +
		"FROM Win32_NTLogEvent WHERE Logfile = '%s' AND EventCode = %d AND TimeGenerated > '%%s'"
	return []Query{
		// root\cimv2: 420/h. Services, drivers and the two log-clear queries
		// are Esinta collectors at 2 min; process lookups by PID take the rest
		// (the audit lines carry no query text, so that split is derived).
		{Key: "proc_pid", Namespace: NSCimv2, WQL: "SELECT " + procCols + " FROM Win32_Process WHERE ProcessId = %d",
			PerHour: 276, Class: "Win32_Process", Truth: TruthPID, KeyProp: "ProcessId", Composite: true},
		{Key: "proc_all", Namespace: NSCimv2, WQL: "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate FROM Win32_Process",
			PerHour: 12, Class: "Win32_Process", Truth: TruthProcSet, KeyProp: "ProcessId", Composite: true, ImpossibleEmpty: true},
		{Key: "svc", Namespace: NSCimv2, WQL: "SELECT Name, DisplayName, PathName, StartMode, StartName, State, ServiceType, Description, ProcessId FROM Win32_Service",
			PerHour: 30, Class: "Win32_Service", Truth: TruthServices, KeyProp: "Name", Composite: true, ImpossibleEmpty: true},
		{Key: "drv", Namespace: NSCimv2, WQL: "SELECT Name, DisplayName, PathName, StartMode, StartName, State, ServiceType, Description FROM Win32_SystemDriver",
			PerHour: 30, Class: "Win32_SystemDriver", Truth: TruthDrivers, KeyProp: "Name", Composite: true, ImpossibleEmpty: true},
		{Key: "evt_sec", Namespace: NSCimv2, WQL: fmt.Sprintf(evtFmt, "Security", 1102),
			PerHour: 30, Class: "Win32_NTLogEvent", Truth: TruthNone},
		{Key: "evt_sys", Namespace: NSCimv2, WQL: fmt.Sprintf(evtFmt, "System", 104),
			PerHour: 30, Class: "Win32_NTLogEvent", Truth: TruthNone},
		{Key: "ns_ctl", Namespace: NSCimv2, WQL: "SELECT Name FROM __NAMESPACE",
			PerHour: 12, Class: "__NAMESPACE", Repository: true, Truth: TruthKeySet, KeyProp: "Name", Composite: true, ImpossibleEmpty: true},

		// root\StandardCimv2: firewallrules collector, 4 queries / 5 min.
		{Key: "fw_rules", Namespace: NSStandardCimv2, WQL: "SELECT InstanceID, DisplayName, DisplayGroup, Enabled, Direction, Action, Profiles, Owner, " +
			"PolicyStoreSource, PolicyStoreSourceType, EnforcementStatus, EdgeTraversalPolicy FROM MSFT_NetFirewallRule",
			PerHour: 12, Class: "MSFT_NetFirewallRule", Truth: TruthKeySet, KeyProp: "InstanceID", Registry: "fwrules", Composite: true, ImpossibleEmpty: true},
		{Key: "fw_port", Namespace: NSStandardCimv2, WQL: "SELECT InstanceID, Protocol, LocalPort, RemotePort FROM MSFT_NetProtocolPortFilter",
			PerHour: 12, Class: "MSFT_NetProtocolPortFilter", Truth: TruthKeySet, KeyProp: "InstanceID", Registry: "fwrules", Composite: true, ImpossibleEmpty: true},
		{Key: "fw_app", Namespace: NSStandardCimv2, WQL: "SELECT InstanceID, Program, Package FROM MSFT_NetApplicationFilter",
			PerHour: 12, Class: "MSFT_NetApplicationFilter", Truth: TruthKeySet, KeyProp: "InstanceID", Registry: "fwrules", Composite: true, ImpossibleEmpty: true},
		{Key: "fw_addr", Namespace: NSStandardCimv2, WQL: "SELECT InstanceID, LocalAddress, RemoteAddress FROM MSFT_NetAddressFilter",
			PerHour: 12, Class: "MSFT_NetAddressFilter", Truth: TruthKeySet, KeyProp: "InstanceID", Registry: "fwrules", Composite: true, ImpossibleEmpty: true},

		// Defender: defenderstate collector, 2 queries / 2 min.
		{Key: "def_status", Namespace: NSDefender, WQL: "SELECT * FROM MSFT_MpComputerStatus",
			PerHour: 30, Class: "MSFT_MpComputerStatus", Truth: TruthExactlyOne, Composite: true, ImpossibleEmpty: true},
		{Key: "def_pref", Namespace: NSDefender, WQL: "SELECT * FROM MSFT_MpPreference",
			PerHour: 30, Class: "MSFT_MpPreference", Truth: TruthExactlyOne, Composite: true, ImpossibleEmpty: true},

		// root\subscription: wmisubscriptions collector, 5 queries / 5 min.
		// May be legitimately empty on a clean VM; invariants then hold at 0.
		{Key: "sub_filter", Namespace: NSSubscription, WQL: "SELECT Name, Query, QueryLanguage, EventNamespace FROM __EventFilter",
			PerHour: 12, Class: "__EventFilter", Repository: true, Truth: TruthKeySet, KeyProp: "Name", Composite: true},
		{Key: "sub_consumer", Namespace: NSSubscription, WQL: "SELECT Name FROM __EventConsumer",
			PerHour: 12, Class: "__EventConsumer", Truth: TruthKeySet, KeyProp: "Name", Composite: true},
		{Key: "sub_cmdline", Namespace: NSSubscription, WQL: "SELECT Name, CommandLineTemplate, ExecutablePath, WorkingDirectory, RunInteractively FROM CommandLineEventConsumer",
			PerHour: 12, Class: "CommandLineEventConsumer", Truth: TruthKeySet, KeyProp: "Name", Composite: true},
		{Key: "sub_script", Namespace: NSSubscription, WQL: "SELECT Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer",
			PerHour: 12, Class: "ActiveScriptEventConsumer", Truth: TruthKeySet, KeyProp: "Name", Composite: true},
		{Key: "sub_binding", Namespace: NSSubscription, WQL: "SELECT Filter, Consumer FROM __FilterToConsumerBinding",
			PerHour: 12, Class: "__FilterToConsumerBinding", Repository: true, Truth: TruthCount, Composite: true},

		// TaskScheduler: scheduledtasks collector, 2 queries / 5 min.
		{Key: "task", Namespace: NSTaskScheduler, WQL: "SELECT TaskName, TaskPath, State FROM MSFT_ScheduledTask",
			PerHour: 12, Class: "MSFT_ScheduledTask", Truth: TruthCount, Registry: "tasks", Composite: true, ImpossibleEmpty: true},
		{Key: "task_info", Namespace: NSTaskScheduler, WQL: "SELECT TaskName, TaskPath, LastRunTime, NextRunTime, LastTaskResult FROM MSFT_ScheduledTaskInfo",
			PerHour: 12, Class: "MSFT_ScheduledTaskInfo", Truth: TruthCount, Registry: "tasks", Composite: true, ImpossibleEmpty: true},

		// hostposture collector, 1 query per namespace / 5 min. Left out at run
		// time when the namespace is absent (pre-flight or -skip-ns).
		{Key: "devguard", Namespace: NSDeviceGuard, WQL: "SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning, SecurityServicesConfigured FROM Win32_DeviceGuard",
			PerHour: 12, Class: "Win32_DeviceGuard", Truth: TruthCount, Composite: true},
		{Key: "bitlocker", Namespace: NSVolumeEncrypt, WQL: "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume",
			PerHour: 12, Class: "Win32_EncryptableVolume", Truth: TruthCount, Composite: true},
		{Key: "tpm", Namespace: NSTpm, WQL: "SELECT IsEnabled_InitialValue, IsActivated_InitialValue, IsOwned_InitialValue, SpecVersion FROM Win32_Tpm",
			PerHour: 12, Class: "Win32_Tpm", Truth: TruthCount, Composite: true},
	}
}

// stressWeight are the arm-X multipliers (design §4.1): array-heavy and
// large-result queries at 5x their production share.
var stressWeight = map[string]float64{
	"proc_all": 5, "fw_rules": 5, "fw_port": 5, "fw_app": 5, "fw_addr": 5, "def_pref": 5,
}

// Stress returns the arm-X catalog: Production with stressWeight applied.
// It is not production-shaped and is reported as such.
func Stress() []Query {
	qs := Production()
	for i := range qs {
		if w, ok := stressWeight[qs[i].Key]; ok {
			qs[i].PerHour *= w
		}
	}
	return qs
}

// ByName returns the named mix ("production" or "stress").
func ByName(mix string) ([]Query, error) {
	switch mix {
	case "production":
		return Production(), nil
	case "stress":
		return Stress(), nil
	}
	return nil, fmt.Errorf("unknown mix %q (production | stress)", mix)
}

// Without drops the queries in the given namespaces (case-insensitive).
func Without(qs []Query, namespaces []string) []Query {
	skip := map[string]bool{}
	for _, ns := range namespaces {
		skip[strings.ToLower(ns)] = true
	}
	out := qs[:0:0]
	for _, q := range qs {
		if !skip[strings.ToLower(q.Namespace)] {
			out = append(out, q)
		}
	}
	return out
}

// Only keeps the queries with the given keys (for focused runs such as B1).
func Only(qs []Query, keys []string) []Query {
	keep := map[string]bool{}
	for _, k := range keys {
		keep[k] = true
	}
	out := qs[:0:0]
	for _, q := range qs {
		if keep[q.Key] {
			out = append(out, q)
		}
	}
	return out
}

// Namespaces lists the distinct namespaces of qs, sorted, cimv2 first.
func Namespaces(qs []Query) []string {
	seen := map[string]bool{}
	var out []string
	for _, q := range qs {
		if !seen[q.Namespace] {
			seen[q.Namespace] = true
			out = append(out, q.Namespace)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i] == NSCimv2) != (out[j] == NSCimv2) {
			return out[i] == NSCimv2
		}
		return out[i] < out[j]
	})
	return out
}

// PerHourTotal sums the catalog's rates at k = 1.
func PerHourTotal(qs []Query) float64 {
	var t float64
	for _, q := range qs {
		t += q.PerHour
	}
	return t
}

// Hash is a short stable fingerprint of the catalog (keys, WQL, rates), for
// meta.json.
func Hash(qs []Query) string {
	h := uint32(2166136261)
	for _, q := range qs {
		for _, b := range fmt.Appendf(nil, "%s|%s|%s|%g;", q.Key, q.Namespace, q.WQL, q.PerHour) {
			h ^= uint32(b)
			h *= 16777619
		}
	}
	return fmt.Sprintf("%08x", h)
}

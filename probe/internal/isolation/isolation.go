// Package isolation checks that a probe host runs no other WMI-heavy
// software (design §8). Other WMI clients load the same WmiPrvSE
// hosts and Winmgmt, so their traffic would contaminate the metrics.
package isolation

import (
	"sort"
	"strings"

	"golang.org/x/sys/windows"

	"wmiresearch/probe/internal/sysinfo"
)

// Known WMI-heavy services: the Esinta agent itself, and common management
// and monitoring agents that poll WMI.
var heavyServices = map[string]string{
	"esintaendpoints": "Esinta Endpoints agent",
	"ccmexec":         "SCCM / ConfigMgr client",
	"healthservice":   "SCOM / Microsoft Monitoring Agent",
	"splunkforwarder": "Splunk forwarder (WMI inputs)",
	"zabbix agent":    "Zabbix agent",
	"zabbix agent 2":  "Zabbix agent 2",
	"nscp":            "NSClient++",
	"datadogagent":    "Datadog agent",
	"prtg probe":      "PRTG probe",
	"snmp":            "SNMP service (WMI-backed MIBs)",
}

// Known WMI-heavy interactive processes.
var heavyProcesses = map[string]string{
	"servermanager.exe": "Server Manager (polls WMI while open)",
	"wbemtest.exe":      "WMI tester",
	"esinta-agent.exe":  "Esinta agent",
}

// Finding is one reason the host is not clean.
type Finding struct {
	Kind, Name, Why string
}

// Check lists running WMI-heavy services and processes.
func Check() ([]Finding, error) {
	var out []Finding
	svcs, err := sysinfo.Services(windows.SERVICE_WIN32)
	if err != nil {
		return nil, err
	}
	for _, s := range svcs {
		if why, ok := heavyServices[strings.ToLower(s.Name)]; ok && s.State == windows.SERVICE_RUNNING {
			out = append(out, Finding{"service", s.Name, why})
		}
	}
	snap, err := sysinfo.ProcessSnapshot()
	if err != nil {
		return nil, err
	}
	for _, p := range snap {
		if why, ok := heavyProcesses[strings.ToLower(p.Name)]; ok {
			out = append(out, Finding{"process", p.Name, why})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

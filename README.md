# WMI degradation research

Research on degradation of long-lived WMI COM connections (memory growth, query latency creep, silent failures) and on refresh strategies, measured with a correct-client probe on lab hosts.

| Path | Contents |
|---|---|
| `docs/probe-v2-design.md` | The design, including the pass criteria fixed before the runs |
| `probe/` | `probe2`, the correct-client probe (Windows-only Go); see `probe/README.md` |
| `analysis/` | Self-test gate (`gate.py`), fault summary (`efault.py`), foreign-WMI check (`foreign.py`), host slopes and figures |
| `tools/` | `probe_task.py` starts a probe run as a scheduled task on a lab host; `host_events.py` harvests background events with `wevtutil` |
| `docs/runs/` | Run logs: every host action, in order |
| `paper/` | Paper source and figures |
| `results/` | Run outputs (not in git; published as the release asset `wmi-degradation-results-2026-10-26.tar`) |

The two lab hosts are pseudonymised throughout the logs, paper source and data: `win10-lab` is the Windows 10-based host (Windows Server 2019, build 17763), and `win11-lab` is the Windows 11-based host (build 26200). The run logs also call them by their SSH aliases, `win2` and `win11`. Lab login accounts, addresses and the MAC address are replaced by `[lab account]`, `[lab IP]` and `[lab MAC]`. No measured value was changed. The release's `DATA-README.md` lists the replacements made in the data.

`tools/probe_task.py` and `tools/host_events.py` reach the lab hosts through an SSH helper, `tools/lab_ssh.py`, which is not included. Any helper with the interface `lab_ssh.py <target> run|ps|get|put <args>` (cmd command, PowerShell command, download, upload) will do.

## Licence

Code (`probe/`, `analysis/`, `tools/`) is licensed under the Apache License 2.0 (`LICENSE`). The paper, documentation and data are licensed under CC BY 4.0 (`LICENSE-CC-BY-4.0`).

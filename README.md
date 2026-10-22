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
| `results/` | Run outputs (not in git; published as a release asset) |

`tools/probe_task.py` and `tools/host_events.py` reach the lab hosts through an SSH helper, `tools/lab_ssh.py`, which is not included. Any helper with the interface `lab_ssh.py <target> run|ps|get|put <args>` (cmd command, PowerShell command, download, upload) will do.

## Licence

Code (`probe/`, `analysis/`, `tools/`) is licensed under the Apache License 2.0 (`LICENSE`). The paper, documentation and data are licensed under CC BY 4.0 (`LICENSE-CC-BY-4.0`).

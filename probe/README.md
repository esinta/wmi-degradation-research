# probe2: correct-client WMI degradation probe

Implements `docs/probe-v2-design.md`. Windows-only Go (`go-ole`, `x/sys/windows`).

**Before any run on a host:** confirm the hostname/IP with the user, that the host is lab-only and idle, and that the user approved the run (CLAUDE.md ground rules). `probe2` itself refuses to run when it sees the Esinta agent or another WMI-heavy agent running.

## Layout

| Package | Role (design §) |
|---|---|
| `internal/sta` | One locked STA thread per connection + process-lifetime anchor STA (§2.1). `ModeMTA` exists only for buggy arm B2 |
| `internal/wmi` | The client: `Dial`, `Query` (deadline/abandon, late results), strict enumeration (no `oleutil.ForEach`), `Properties_` reads, full EXCEPINFO capture, per-query VARIANT ledger (§2.2–2.3) |
| `internal/ledger` | Proves every acquired COM reference was released exactly once |
| `internal/catalog` | Esinta's WQL at the measured production rates (§3.1); `stress` mix for arm X |
| `internal/sched` | Fixed-rate, seeded schedule at k × production (§3.2) |
| `internal/strategy` | none / timed / adaptive / pool (Esinta semantics) (§4.1) |
| `internal/truth` | Non-WMI ground truth and silent classes S1–S5 (§6.6) |
| `internal/sysinfo` | NtQuerySystemInformation, SCM, modules, accounts, host counters, registry counts. No WMI |
| `internal/sampler` | 10 s samples: probe, each WmiPrvSE, Winmgmt host, host CPU/memory/disk, canary (§6.4, §7) |
| `internal/clock` | QueryPerformanceCounter durations (Go's monotonic clock steps ~0.5 ms on Windows) |
| `internal/abort` | Hard abort thresholds (§9) |
| `internal/out` | Hourly-rotated, gzipped CSVs; schemas (§6) |
| `internal/runner` | One arm end to end |
| `internal/preflight` | Per-host checks and the k ramp (§8) |
| `internal/isolation` | Refuses hosts running WMI-heavy software |

## Build (fine on the dev laptop)

```bash
bash probe/scripts/build.sh     # gofmt, vet, unit tests, then dist/probe2.exe + dist/wmi-integration.test.exe
```

Unit tests use fakes and native read-only APIs; none makes a WMI call. The real-WMI tests (`-tags wmiintegration`) are compiled into `dist/wmi-integration.test.exe` and run only on a probe host.

## On a probe host (after approval)

`<t>` is the `tools/lab_ssh.py` target of the approved VM. Run from the repo root with `PYTHONIOENCODING=utf-8 MSYS_NO_PATHCONV=1`.

The probe runs as LocalSystem, like Esinta, via a one-shot scheduled task. An SSH session would end with the connection, and Defender and Security-log queries need the privileges.

```bash
# 1. Copy the binaries
python tools/lab_ssh.py <t> run "mkdir C:\probe"
python tools/lab_ssh.py <t> put probe/dist/probe2.exe C:/probe/probe2.exe
python tools/lab_ssh.py <t> put probe/dist/wmi-integration.test.exe C:/probe/wmi-integration.test.exe

# 2. Smoke test: real-WMI integration tests (a few seconds of WMI calls)
python tools/lab_ssh.py <t> run "C:\probe\wmi-integration.test.exe -test.v"

# 3. Pre-flight (≈ 60 min idle + 30 min unload watch + 6 × 10 min ramp)
python tools/probe_task.py <t> preflight -- preflight -ramp 1,5,10,20,50,100
python tools/lab_ssh.py <t> run "type C:\probe\logs\preflight-*.log"
```

`tools/probe_task.py` creates the task from XML: LocalSystem, priority 4 (normal) and **no execution time limit**. Do not use `schtasks /Create /TR` for arms. Such tasks run below normal and are killed after the 72 h default limit, which would cut H, M and L. `probe2` also raises itself to normal priority and records `priority_class` in `meta.json`.

Each arm is `python tools/probe_task.py <t> <arm> -- <args>`. `PF` below is the `preflight.json` path, and `KH` is `k_h` from it.

| Arm | probe2 args |
|---|---|
| ST-1 + ST-3 | `run -arm ST-1 -k KH -duration 6h -release-test 1h -preflight PF` |
| ST-2 | `run -arm buggy-ST-2 -client-class buggy -bug array-leak -k KH/10 -duration 1h -preflight PF` |
| H | `run -arm H -k KH -duration 72h -preflight PF` |
| X | `run -arm X -mix stress -k KH -duration 48h -preflight PF` |
| M | `run -arm M -k KH/10 -duration 168h -preflight PF` |
| L | `run -arm L -k 1 -duration 504h -preflight PF` |
| E1 | `run -arm E1 -strategy timed -timed-interval 1h -k KH -duration 72h -preflight PF` |
| E2 | `run -arm E2 -strategy adaptive -k KH -duration 72h -preflight PF` |
| E3 | `run -arm E3 -strategy pool -k KH -duration 72h -preflight PF` |
| B1 | `run -arm buggy-B1-hi -client-class buggy -bug array-leak -k KH/10 -duration 4h -preflight PF`, then `-arm buggy-B1-lo -k KH/40` |
| B2 | `run -arm buggy-B2-c1 -client-class buggy -bug cross-apartment -cimv2-conns 1 -k KH -duration 4h -preflight PF`, then `-arm buggy-B2-c5 -cimv2-conns 5` |

**Inspecting a probe host:** use only non-WMI tools (tasklist, sc, schtasks, reg, wevtutil, `Get-Process`, `Get-Service`). `Get-CimInstance`, `Get-WmiObject`, `Get-NetIPAddress`, `Get-ScheduledTask`, `Get-Mp*` and `Get-NetFirewall*` all go through WMI and start provider hosts.

Write the arithmetic out (e.g. `-k 5` for KH/10 when KH = 50).

**Results** go to `C:\probe\results\<host>\<arm>\<run_id>\`. Zip a run and fetch it:

```bash
python tools/lab_ssh.py <t> ps "Compress-Archive C:\probe\results\<host>\<arm>\<run_id> C:\probe\<arm>-<run_id>.zip"
python tools/lab_ssh.py <t> get C:/probe/<arm>-<run_id>.zip results/<host>/<arm>/<arm>-<run_id>.zip
```

## Outputs

`queries`, `connections`, `procs`, `host`, `events` and `truth` CSVs (hourly, gzipped), plus `meta.json`. The columns are in `internal/out/schema.go` (design §6). Durations are milliseconds, from QPC.

`silent_mask` bits:

| Bit | Value | Class |
|---|---|---|
| S1 | 1 | impossible empty |
| S2 | 2 | truncated |
| S3 | 4 | enumeration ended with an error |
| S4 | 8 | skipped objects/properties |
| S5 | 16 | phantom or mismatched content |

## Not yet implemented (increment 2)

- ETW foreign-WMI-client meter (design §7). Isolation is checked at start only, via the service and process lists.
- WMI-Activity event 5857 cross-check of provider attribution. Attribution uses loaded provider DLLs only.
- `wevtapi` ground truth for the two event-log queries (truth kind `none` for now).
- E-fault injection, the X-raw native `IWbemServices` client, and the analysis scripts.

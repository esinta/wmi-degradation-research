# win2 run log (win10-lab, [lab IP])

Server 2019 Standard Evaluation 10.0.17763.3650, 2 vCPU / 4 GB. Lab-only; probe runs approved by the user on 2026-10-17.
Host prep (by the user, 2026-10-17 19:00:37Z; notes in `C:\ProgramData\EsintaSoak\probe-prep-2026-10-17.txt` on the host):
EsintaEndpoints stopped + Disabled, `\EsintaMem` sampler task removed, `DoNotOpenServerManagerAtLogon=1`.
Not changed: Defender real-time protection on, daily quick scan ~02:00 local (UTC-7) = ~09:00Z; Windows Update not paused.
Winmgmt already runs alone in its svchost (PID 2432 at 2026-10-17), so no `/standalonehost` needed.

Times are UTC. Every entry that touched WMI on the host is marked **[WMI]**.

| UTC | What |
|---|---|
| 2026-10-17 19:13:19 | **[WMI]** My host check ran `Get-CimInstance Win32_OperatingSystem` and `Get-NetIPAddress` (CIM) by mistake: WmiPrvSE PID 6004 started at that second. `Get-ScheduledTask` (CIM) ran ~1 min later. From here on, host inspection uses only non-WMI tools (tasklist, sc, schtasks, reg, Get-Process, wevtutil). |
| 2026-10-17 19:14 | WmiPrvSE at handover check: PID 3376 (since 2026-09-29, 162 handles), PID 6004 (mine, 220 handles). The ~1,900-handle host the user saw is gone. |
| 2026-10-17 19:14:16 | Copied `probe2.exe` (538f4b683b72, sha256 7d7e8295…) and `wmi-integration.test.exe` (dd435391…) to `C:\probe`; hashes verified on the host. |
| 2026-10-17 19:14:26–27 | **[WMI]** `wmi-integration.test.exe -test.v` over SSH (account [lab account]): 6/6 real-WMI tests pass (clean client, array-leak arm leaks, cross-apartment flagged, invalid-namespace code, abandon + late result). **H-enum confirmed**: invalid class fails only at `Objects.Next` (WBEM_E_INVALID_CLASS); go-ole `ForEach` returns nil error, 0 items. |
| 2026-10-17 19:14:58 | **[WMI]** Pre-flight started as SYSTEM via `schtasks /TR` (task `probe2`): `probe2 preflight -ramp 1,5,10,20,50,100` (60 min idle → namespace/provider checks → 30 min unload watch → 6 × 10 min ramp). Run `20261017T191458Z`. Process ran **BelowNormal** (task default priority 7): affects only the ramp, only under contention. |
| 2026-10-17 19:17 | Tested `tools/probe_task.py` with `probe2 version` (no WMI): XML task, SYSTEM, priority 4, no time limit; exit 0. Task deleted. |

# Run log: win11 = win11-lab ([lab IP])

This follows `win2-log.md`. Every host action is listed, and WMI-touching ones are marked **[WMI]**. Times are UTC.

**Approval:** the user requested the run on 2026-10-18 ("Replicate the full WMI test battery on a new Windows 11 host"). The user confirmed win11-lab is their lab VM, named to mimic an OT device, on an isolated RFC1918 lab network. Methodology is unchanged from win2: same probe, `analysis/gate.py`, `analysis/efault.py`, k values, windows and `results/` layout.

## Environment block (2026-10-18 23:19–23:25Z, non-WMI tools only)

| Item | Value | Source |
|---|---|---|
| Hostname / IP / MAC | win11-lab / [lab IP] (DHCP) / [lab MAC] (Proxmox VM, Intel PRO/1000 MT emulated NIC) | `hostname`, user's `ipconfig /all` screenshot |
| OS | **Windows 11 Home** (EditionID `Core`, InstallationType Client), 25H2, **build 26200.6899**. The registry ProductName reads "Windows 10 Home", a known Win11 quirk | `reg query …\CurrentVersion` |
| CPU | 2 logical processors, "AMD64 Family 15 Model 107, AuthenticAMD", which is QEMU's generic `kvm64` model | `%NUMBER_OF_PROCESSORS%`, `%PROCESSOR_IDENTIFIER%` |
| RAM | 8,567,402,496 B (8 GiB). win2 has 4 GB | .NET `ComputerInfo.TotalPhysicalMemory` |
| Boot | 2026-10-18 21:57:08Z (14:57:08 PDT), after the user's snapshot rollback and restart | `net statistics workstation` |
| Clock | in sync with the laptop (VM 23:19:48.75Z vs laptop 23:19:33 at the start of the SSH call) | .NET `DateTime.UtcNow` |
| Account | `win11-lab\[lab account]`, member of BUILTIN\Administrators | `whoami /groups` |
| Defender | WinDefend running; no `DisableRealtimeMonitoring` (real-time on); scheduled-scan task has no fixed trigger (Home: automatic maintenance), so scans are harvested from the Defender event log after each arm | `sc query`, `reg query`, `schtasks` |
| Firewall | **all profiles OFF** at 23:19Z: the user disabled them while troubleshooting SSH. **Active network profile: Public** (NetworkList Category 0, "Network"). The only SSH rule ("OpenSSH SSH Server (sshd)", TCP 22, any remote IP) is scoped to **Private only**, which caused the SSH timeouts | `netsh advfirewall`, `reg query …\NetworkList\Profiles` |
| **Winmgmt svchost** | **own process**: Winmgmt is the only service in svchost PID 2968 (`-k netsvcs -p`, no `SvcHostSplitDisable`). `SvcHostSplitThresholdInKB` = 0x380000 (3.5 GiB) < 8 GiB RAM. 5 of 81 running service PIDs host more than one service (BFE+mpssvc, the DcomLaunch group, KeyIso/SamSs/VaultSvc, RpcEptMapper+RpcSs, the per-user Unistore group). **Same as Server 2019** (alone in PID 5316 there) | `sc queryex`, `reg query` |
| Interactive session | a user is logged on at the console: explorer, OneDrive (+Sync service), Widgets/WidgetService, SearchHost/SearchIndexer, CrossDeviceResume, msedgewebview2, SecurityHealthSystray, the user's elevated PowerShell. A WmiPrvSE was already running. No Esinta or other management agent seen | `Get-Process` |
| Busiest processes since boot | MsMpEng 666 CPU-s, System 196, svchost 1792 (SysMain) 120, lsass 50 | `Get-Process` |

**[WMI] before any measurement:** the user ran `Test-NetConnection`, `Get-NetFirewallProfile` and `Get-NetConnectionProfile`/`Get-NetFirewallRule` (CIM cmdlets) at the console while troubleshooting, ~23:00–23:19Z. This was before the idle baseline, so it doesn't affect it.

## Actions

| UTC | Action |
|---|---|
| 2026-10-18 21:35–22:48 | SSH to the VM timed out on 22/445/3389/5985 from the laptop, and on 22/445 from win2 (non-WMI .NET TcpClient, logged in win2-log). ARP resolved to the right MAC. |
| 2026-10-18 23:19:17 | After the user disabled the firewall: port 22 answers (`SSH-2.0-OpenSSH_for_Windows_9.5`). |
| 2026-10-18 23:19–23:25 | Environment block above (`hostname`, `whoami`, `reg query`, `net statistics`, .NET, `sc`, `schtasks`, `netsh`, `Get-Process`). No WMI. |
| 2026-10-18 23:21:45 | User chose "extend sshd rule to Public": `netsh advfirewall firewall set rule name="OpenSSH SSH Server (sshd)" dir=in new profile=private,public` (Allow, TCP 22). |
| 2026-10-18 23:21:48 | `netsh advfirewall set allprofiles state on`: **firewall ON for all profiles**, as on win2. A new SSH session connects (23:21:50). The network stays on Win11's default, Public. No WMI. |
| 2026-10-18 23:22:25 | Deployed probe2 **c4d1794036e4** to `C:\probe\probe2.exe` (sha256 45d83a01…, verified with certutil; `probe2 version`). This is the same build as win2's E-fault and H runs, with WMI client code identical to win2's ST-1/ST-2 build 379cdbca207a. 32 GB free. |
| 2026-10-18 23:23:29–23:23:32 | **[WMI]** SKU checks, `tools/win_sku_checks.ps1` → `results/win11-lab/sku/sku-20261018.json`. Before pre-flight's idle baseline. Results below. |
| 2026-10-18 23:24 | Non-WMI follow-up: `reg query …\Services\vwifibus` and `dir` of its binary on win11 and win2. |

## SKU-sensitive facts (before the timed runs)

| Item | Windows 11 Home 26200 (win11-lab) | Server 2019 17763 (win2) |
|---|---|---|
| Winmgmt svchost | **own** (PID 2968, only Winmgmt; split threshold 3.5 GiB < 8 GiB) | **own** (pre-flight 2026-10-17 recorded `winmgmt_host_services: ["Winmgmt"]` for PID 2432; today PID 5316, also alone) |
| Drivers: SCM vs `Win32_SystemDriver` | 384 vs **384 for every selection** (Name; Name, State; catalog `drv`; `*`; Name + each of DisplayName, PathName, StartMode, StartName, ServiceType, Description). **No omission.** | 334 vs 333 when any configuration property is selected: `vwifibus` omitted |
| `vwifibus` | registered; ImagePath `\SystemRoot\System32\DriverStore\FileRepository\netvwifibus.inf_amd64_…\vwifibus.sys`, **binary present** (65,536 B) and returned by WMI | registered; ImagePath `\SystemRoot\System32\drivers\vwifibus.sys`, **binary absent**, omitted. Consistent with "a registered driver whose binary is missing is dropped"; Win11 has no such driver, so the omission cannot occur on this host |
| `SELECT Name FROM __EventConsumer` | fails: "Invalid query" (Get-CimInstance) | fails, 0x80041017 at Next |
| `__EventConsumer` properties | CreatorSID, MachineName, MaximumQueueSize (no Name). All 5 derived consumers (LogFile, ActiveScript, NTEventLog, SMTP, CommandLine) have Name | same (paper) |
| `SELECT InstanceID, Program, Package FROM MSFT_NetApplicationFilter` | fails: "Invalid query" | fails, 0x80041017 at Next |
| `MSFT_NetApplicationFilter` properties (Get-CimClass) | … InstanceID, Name, …, **AppPath, Package**; **no Program** | AppPath, no Program (paper; see the win2 row in draft2-pending) |
| `… FROM MSFT_ScheduledTaskInfo` | fails: "Invalid class" | fails, 0x80041010 at Next |
| `MSFT_ScheduledTaskInfo` / `MSFT_TaskDynamicInfo` | not found / exists: LastRunTime, LastTaskResult, NextRunTime, NumberOfMissedRuns, TaskName, TaskPath | not a class / (paper cites the doc) |
| `__CacheControl` ClearAfter | EventConsumerProvider 30 s, **EventSink 15 s**, EventProvider 30 s, ObjectProvider 30 s, PropertyProvider 30 s | 30, 30, 15, 30, 30 s (same five values) |
| `__ProviderHostQuotaConfiguration` | MemoryPerHost 536,870,912; MemoryAllHosts 1,073,741,824; ThreadsPerHost 256; HandlesPerHost 4,096; ProcessLimitAllHosts 32 | **identical** |

The probe's strict-loop codes for the three failing queries (which call fails, and the HRESULT) come from pre-flight's catalog check. The Get-CimInstance messages above come through the MI client and only show that each query fails.
| 2026-10-18 23:24:41 | Non-WMI `Get-Process WmiPrvSE`: none running. The hosts from the SKU checks have exited. |
| 2026-10-18 23:24:47 | **[WMI]** **Pre-flight started**: `probe_task.py win11 preflight -- preflight -ramp 1,5,10,20,50,100` (c4d1794036e4; SYSTEM, Normal priority; ETW meter always on). Defaults as in win2's pre-flight of record: 60 min idle baseline, namespace/provider/catalog checks, 30 min unload watch, 6 × 10 min ramp. Log `C:\probe\logs\preflight-20261018T232447Z.log`; results under `C:\probe\results\win11-lab\`. Expected end ≈01:30Z. The console session stays logged on; the idle meter measures its WMI traffic. |
| 2026-10-18 23:27 | Laptop: built **probe2 067432eb9e20** (`probe/dist/probe2-midq.exe`, sha256 5202bb13…) with the mid-query kill (`-fault-kill-inflight`, `-fault-kill-repeat`, `-fault-kill-every`; off by default). Unit tests pass (fakes only; real-WMI tests are behind the `wmiintegration` tag and did not run). Used only for a separate, labelled E-midq arm after the battery. The battery runs c4d1794036e4 (`probe/dist/probe2.exe`, unchanged). |
| 2026-10-19 00:24:50 | Pre-flight idle baseline (60 min, ETW meter): **15 foreign WMI operations from 1 process (15/h)**, under the design's 60/h limit, with the console session logged on. Provider/hosting map identical to win2: CIMWin32, ntevt, wfascim, schedprov, DeviceGuard, EncryptableVolume and TPM in **NetworkServiceHost**; ProtectionManagement (Defender) in **LocalServiceHost**. |
| 2026-10-19 00:24:50–53 | Catalog check (probe strict loop): 20 of 23 keys ok; **the same three fail as on win2**: `fw_app` WBEM_E_INVALID_QUERY, `sub_consumer` WBEM_E_INVALID_QUERY, `task_info` WBEM_E_INVALID_CLASS. `drv` returns 384 rows (= SCM). H-enum: **CONFIRMED** on Win11 too (`oleutil.ForEach` reports success with 0 items; the strict loop sees WBEM_E_INVALID_CLASS at `Objects.Next`). Noted: `sub_filter` and `sub_binding` each return 1 row (a built-in subscription exists on this host). Unload watch (30 min) then ramp (6 × 10 min); expected end ≈01:55Z (corrects the ≈01:30Z estimate above, which left out the unload watch). |
| 2026-10-19 00:27:32 | During the unload watch: copied `probe2-midq.exe` (067432eb9e20) to `C:\probe\probe2-midq.exe`; certutil sha256 5202bb13… matches the laptop build; `probe2-midq version` → 067432eb9e20. File copy only, no WMI. `tools/probe_task.py` gained `--exe <file>`, so the E-midq task can run that build; the battery uses the default `probe2.exe`. |
| 2026-10-19 00:28:15 | CPU model, from `reg query HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` (no WMI), on both hosts: **win2 "AMD Ryzen 9 9955HX 16-Core" (Family 26 Model 68; host passthrough)**; **win11 "QEMU Virtual CPU version 2.5+" (Family 15 Model 107; generic kvm64, no modern ISA extensions)**. Both report ~MHz 2,495, so probably the same Proxmox node. Absolute latencies and CPU % are therefore **not comparable across the two hosts**; compare within-host trends (slopes, ratios) only. |
| 2026-10-19 00:54:54–01:54:55 | **[WMI]** Pre-flight ramp (10 min per step, 0 dropped at every step). Induced CPU / host CPU: k=1 0.6 / 6.1 %; k=5 2.8 / 8.8 %; k=10 5.5 / 12.1 %; k=20 10.7 / 19.7 %; k=50 27.3 / 41.4 %; **k=100 53.7 / 77.3 %**. Pre-flight written to `C:\probe\results\win11-lab\preflight\20261018T232450Z`; 9 namespaces checked, 14 classes attributed. **k_H = 50** (largest k with induced CPU ≤ 40 %, design §3.2). For comparison, win2 at k=100 used 29.9 %: about 1.8× less CPU per query, consistent with the kvm64 vs host-passthrough CPU difference (00:28:15 row). |
| 2026-10-19 01:55 | **Blocked on a decision.** The request asks for ST-1 at k=100, but on this VM k=100 is above both the 40 % k_H budget and the **50 % probe-induced-CPU hard abort (design §9)**, so the arm would abort after 10 min. Running k=100 would need the abort limit raised, which changes methodology; running k=50 changes the k value. Asked the user. No timed arm started. |
| 2026-10-19 ~04:55 | User's answer: **run at k_H = 50** (design rule), not k=100. |
| 2026-10-19 04:59:24 | **[WMI]** **Battery chain started**: task `probe2-battery` (`probe_task.py win11 battery`, build c4d1794036e4, 300 s settle), PF = `C:/probe/results/win11-lab/preflight/20261018T232450Z/preflight.json`. Steps (logs `C:\probe\logs\battery-20261019T045924Z-<n>.log`): (1) **ST-1** k=50, 6 h, release test 1 h; (2) **buggy-ST-2** k=5 (= k_H/10, design rule), 1 h; (3) **buggy-ST-2-k10** k=10 (win2's ST-2 rate; second dose), 1 h; (4–7) **E0–E3-fault**, strategies none / timed 1 h / adaptive / pool, k=50, 90 min, provider-host kill at 15 min, Winmgmt restart at 30 min. Flags otherwise verbatim from win2 (`C:\probe\tasks\*.cmd` there). Expected: ST-1 04:59–~11:59 (arm ends ~10:59), ST-2 k5 ~12:04–13:04, ST-2 k10 ~13:09–14:09, E0 ~14:14–15:44, E1 ~15:49–17:19, E2 ~17:24–18:54, E3 ~18:59–20:29Z. |
| 2026-10-19 04:59:26 | ST-1 log: `k=50 (32400 queries/h), 6h0m0s, strategy none, 8 namespaces`, output `ST-1\20261019T045926Z`. **8 namespaces vs win2's 7**: `root\CIMV2\Security\MicrosoftVolumeEncryption` (BitLocker) is present on Win11 and absent on Server 2019 (win2 pre-flight: WBEM_E_INVALID_NAMESPACE), so Win11 runs the catalog's `bitlocker` key and win2 skipped it. This is a SKU difference in the mix, by the design's rule of skipping absent namespaces, not a change of method. |
| 2026-10-19 05:03 | Fetched pre-flight `20261018T232450Z` to `results/win11-lab/preflight/` (tar on the host, no WMI). From `preflight.json`: `winmgmt_pid` 2968, `winmgmt_host_services ["Winmgmt"]` (own svchost, as on win2); `k_h` 50; idle foreign WMI **15.0/h from one client**, a SYSTEM `svchost.exe` (PID 10088) doing `CreateInstanceEnum root\cimv2 : Win32_OperatingSystem` (win2: 3.0/h, `IWbemServices::Connect`). PID 10088 no longer maps to a running service in `sc queryex` at 05:03, so the service is unidentified. **Provider-host unload after idle**: LocalService 60.1 s, NetworkService 60.1 s, SYSTEM host not unloaded (win2: NetworkService 60.0 s, LocalService 65.0 s, SYSTEM not unloaded). `cache_control` and `provider_host_quotas` match the SKU-check JSON and win2. |

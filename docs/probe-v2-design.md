# Probe v2: correct-client accelerated-degradation design (Phase 2)

| | |
|---|---|
| **Date** | 2026-10-16 |
| **Status** | Checkpoint 2. Design only: no builds that run WMI loads, no host changes, no runs |
| **Inputs** | `original-task.md` (brief), `evidence-inventory.md` (Phase 1), Esinta WMI layer at `C:\dev\esinta-endpoints` `780fa92` (read only), `reference/old-probe/`, Esinta agent logs in `C:\Users\user\bisect\wmi-evidence-2026-10-16\` |
| **Answers** | Arms and run matrix (§4), duration per arm (§4.3), how acceleration validity is checked (§5), threats to validity (§10) |

## 0. Bottom line

1. **Acceleration can give a valid result, but only for one kind of degradation, and the design tests which kind applies.**
   - Higher query rate compresses time only if the degradation is driven by **work done**: queries, objects returned, array reads. It does not help if the degradation is driven by **wall-clock time**.
   - The rate-scaling arms (§5) measure the same workload at 1×, 0.1× and the production rate, and give a pre-stated verdict per metric: count-driven, time-driven, mixed, or load-dependent.
   - The accelerated arms support claim A only when the verdict is count-driven.
2. **Acceleration cannot replace one long wall-clock arm.**
   - A purely time-driven mechanism (anything that depends on hours or days, not on work) does not speed up with rate.
   - The only evidence for claim A over weeks is a production-rate, no-refresh arm that runs for weeks: **arm L, 21 days (14 days minimum)**.
   - L is the long pole of the whole plan. Acceleration shortens B, C and E from weeks to days, but not A.
3. **The most likely outcome is a null result. The design makes a null informative.**
   - The prior evidence is:
     - correct-client latency and memory are flat over 0–6 h;
     - the April agent ran about 66 days on Server 2019 and 2022;
     - the old probe claims 7 days with no degradation, without data.
   - So the design pre-registers the smallest effect worth reporting and the detection limit (§5.5). A null then reads as: "no effect ≥ X through N queries per connection (Y× production) and T days".
   - Without an effect, the age-vs-count question has nothing to attribute. Claim B then reduces to a bound on both axes. That is stated up front and is not a design flaw.
4. **An effect that appears only at high rate is a load effect, not aging.** The decision rule labels it that way, and it is never used for claim A.
5. **I found three client-side silent-failure paths in the reference code.** Probe v2 must not inherit them, and they are candidate claim-D findings. Esinta is affected, but this project leaves it untouched (§2.2):
   - go-ole's `oleutil.ForEach` ends silently when `IEnumVARIANT::Next` fails with zero items. A failed enumeration therefore looks like a normal end of results.
   - With `wbemFlagReturnImmediately` (Esinta's flag), many query errors surface during enumeration, not at `ExecQuery`. So a failing query can come back as an **empty success**. This is a hypothesis, to be confirmed first in Phase 3.
   - Esinta's `executeQueryInternal` silently skips an object whose `Properties_` read fails, or a property whose read fails. It also recovers panics without recording them.
   - Query and connect errors keep only the outer `DISP_E_EXCEPTION` HRESULT (`0x80020009`) and the text, not the WBEM `scode` in EXCEPINFO. Only `event_subscription.go:264` reads `SCODE()`.
6. **Calendar:** about 3–3½ weeks on two clean Server 2016 clones, set by the 21-day L arm. With four clones it stays at about 3 weeks, but adds replicates and cross-OS arms. No current lab host is clean (§4.3), so **new clones are needed**. §12 lists the questions for you.

## 1. What the probe must answer

| Claim | Question for probe v2 | Arms |
|---|---|---|
| A | Does a correct client degrade without refresh, beyond the 6 h / ~2.5k queries per connection that production ever reached? | ST (gate), H, X, L |
| B | Does the degradation, if any, follow query count or wall-clock age, and on which "clock": connection, provider host or Winmgmt? | H, M, L (+ E1/E3 for the clock) |
| C | Signatures: latency slope, error codes, silent failures (5 classes, §6.6), WmiPrvSE/Winmgmt growth per attributed process | all correct-client arms |
| D | Size of each client bug's effect on this OS, measured in isolation: #115 leak, #118 cross-apartment, enumeration silent paths | B1, B2 (+ S3/S4 counts in correct arms) |
| E | none vs timed vs adaptive vs pool-equivalent: errors, silent failures, availability, overhead | E0–E3 (+ optional fault phase) |
| F | Do Server 2016 results hold on 2022 / Win10 / Win11? | ST + H on each extra OS, if VMs exist |

**Production reference**, measured from the preserved Esinta logs (the per-query audit lines with `"action":"query_start"`). These logs may have gaps, so the rates are lower bounds.

| Namespace | Win10 lab VM, 53.8 h of logs (q/h) | OT Server 2019, 103.9 h (q/h) | Esinta source of the load |
|---|---|---|---|
| `root\cimv2` | 420.6 | 116.4 | services and drivers every 2 min; event-log query every 2 min; process lookups by PID (the rest) |
| `root\subscription` | 60.0 | 21.7 | `wmisubscriptions`: 5 queries / 5 min |
| `root\Microsoft\Windows\Defender` | 60.0 | 21.8 | `defenderstate`: `SELECT *` from `MSFT_MpComputerStatus` and `MSFT_MpPreference` every 2 min |
| `root\StandardCimv2` | 48.0 | 17.4 | `firewallrules`: rules + 3 filter classes / 5 min |
| `root\Microsoft\Windows\TaskScheduler` | 24.0 | 8.7 | `scheduledtasks`: 2 queries / 5 min |
| DeviceGuard, VolumeEncryption, Tpm | 12.0 each | 4.3 each | `hostposture` / 5 min |

With 6 h recycling, a production cimv2 connection (pool of 2–5) serves at most about 2,500 queries in its life. A per-namespace connection serves at most about 360. **These are the limits of all existing correct-client evidence.**

## 2. The client: correct by construction

### 2.1 Patterns copied from Esinta

These are copied as patterns, not imported.

| Rule | Esinta reference | Probe v2 |
|---|---|---|
| One STA thread per connection, locked for the connection's life; never unlocked, so Go ends the OS thread with it | `sta_thread.go` `staThread.loop` | Same. Every COM call on a connection's objects (`CreateObject`, `ConnectServer`, `Security_`, `ExecQuery`, enumeration, property reads, `Release`) runs on that thread via `run`/`submit` |
| Process-lifetime anchor STA, against the "Cannot find window class" race during back-to-back recycles | `startSTAAnchor` | Same. Started before the first connection, never exits |
| Release on the owning thread; if an abandoned call is still running, release after it returns | `connection.go` `Close`, `releaseIfPending`, `callRunning` | Same |
| Every VARIANT cleared once, `VT_ARRAY` included; by-reference VARIANTs not cleared | `safeVariantClear` (~line 156) | Same rule, plus a ledger that **proves** it at runtime (§2.3) |
| `VT_DISPATCH` results: clearing the VARIANT releases the object; the `ToIDispatch()` cast is not released again | `setSecurity`, `executeQueryInternal` comments | Same |
| `ExecQuery(q, "WQL", wbemFlagReturnImmediately \| wbemFlagForwardOnly)` (semisynchronous, forward-only) | `executeQueryInternal` | Same. Bidirectional enumerators keep result objects alive in WMI; testing that is an optional, labeled arm only |
| Properties read through `Properties_` enumeration (Name, Value) | `executeQueryInternal` | Same, so client cost per object matches production |
| Security: authentication level Packet (3), impersonation Impersonate (3) | `setSecurity` | Same |
| Per-call deadline; abandoned call: connection retired, COM call left to finish on its thread; global cap of 16 in-flight calls | `Query`, `maxInFlightWMICalls`, `abandonedWMICalls` | Same. The counters are written every 10 s, not only in warnings |
| Pool semantics: min 2 / max 5, health check 30 s, idle close 5 min, recycle at 6 h or 50k queries (idle connections only), one cached connection per other namespace with the same recycle rule | `pool.go` (`checkAndRecycleConnections`, `performHealthChecks`), `executor.go` `namespaceConn` | Used **only** in arm E3 (pool-equivalent). The other arms hold fixed connections (§3.3) |

### 2.2 Deliberate deviations from Esinta

Copy Esinta's threading and release rules. Do not copy its error handling.

| Esinta behaviour | Why it matters for the paper | Probe v2 |
|---|---|---|
| `oleutil.ForEach` loop `for item, length, err := enum.Next(1); length > 0; …`: when `Next` fails with 0 items, the loop ends and `ForEach` returns nil (go-ole v1.3.0 `oleutil.go:118`) | A failed enumeration looks like a normal end, giving a truncated or **empty-but-successful** result created by the client library | Own enumeration loop. `S_OK` → item. `S_FALSE` with 0 items → normal end. Anything else → error, recorded as `enum_end_hr` with its row count. Rows that `ForEach` would have reported as success are counted (silent class S3) |
| `ReturnImmediately`: errors such as invalid class, access denied, provider failure or quota violation can appear at the first `Next`, not at `ExecQuery` | Combined with the row above, a failing query could come back as an empty success. **Hypothesis H-enum**: verify first in Phase 3 with one deliberately invalid class on a clean host | Same flags; strict loop records the error |
| `executeQueryInternal` returns nil (skips the object) if `Properties_` fails; skips a property if `Name`/`Value` fails; recovers panics silently | Partial objects with no error = silent failure created by the client | Counted per query: `items_skipped`, `props_failed`, `panics`, each with HRESULT. Never silently dropped |
| Error code = `OleError.Code()` (outer HRESULT, usually `0x80020009` for an IDispatch exception) | WBEM code lost on query and `ConnectServer` paths (inventory gap 4) | Record outer HRESULT **and** EXCEPINFO `scode`, `wCode`, source and description (`OleError.SubError().(ole.EXCEPINFO).SCODE()`) |
| WQL validator, caches, IEC 62443 audit layer, retries with backoff | Not part of the WMI interaction; retries would hide errors | Dropped. No retries in any arm except where a strategy defines them (E2/E3) |

### 2.3 Runtime invariants, asserted per query

Each one is written as a column in `queries.csv` (§6.2). The analysis drops any arm with a non-zero violation count from correct-client results.
- **Thread and apartment:** before each call, `GetCurrentThreadId()` equals the connection's STA thread ID, and `CoGetApartmentType` returns STA. Column: `apt_ok`.
- **VARIANT/IDispatch ledger:** every acquisition is registered: `GetProperty`/`CallMethod` results, enumerator items, `_NewEnum`. Every `VariantClear`/`Release` checks off its entry. Columns: `ledger_outstanding` after the query (must be 0) and `ledger_double` (double clear or release, must be 0). Test builds panic on a double clear.
- **No cross-apartment use by construction:** no object pointer ever leaves its connection's thread. Go code receives only converted Go values: strings, numbers, copied slices.

### 2.4 Self-test gate: no degradation claim until this passes

| Test | Setup | Pass criterion (pre-stated) |
|---|---|---|
| **ST-1 client no-growth** | Correct client, production mix at k_H (§3.2), fixed topology (§3.3), no refresh, **6 h**. That is about 195k queries at k = 50, and on the order of 1M array-property reads per hour, mostly from the firewall filter classes (the dose is measured per query) | After 30 min warm-up, client private bytes: upper 95 % CI of slope < **1.0 MB/h** and < **3 B per array-property read** (1 % of the #115 leak, ~300 B/read). Handles: range ≤ 50 and slope CI upper bound < 1 per 1k queries. Threads constant (anchor + one per connection + fixed Go threads). Go heap flat on the same test. Invariants all 0 |
| **ST-2 positive control** (buggy, labeled) | As ST-1, but array VARIANTs not cleared (re-creates #115), at **k_H/10 for 1 h**. At k_H the leak would be about 300 MB/h (~300 B × ~1M array reads/h), past the probe's own abort limit. At k_H/10 it is about 30 MB/h, still 30× the gate threshold | ST-1's criterion must **fail**, with a leak per array read of the same order as #115 (~300 B). This proves the gate can detect the bug it guards against |
| **ST-3 release test** | Right after ST-1: close all connections (probe stays up with its anchor STA), call `debug.FreeOSMemory`, stay idle **60 min** | Client: private bytes back within 5 MB of the post-warm-up level. Attributed WmiPrvSE hosts and Winmgmt are **measured, not gated**: do they unload or return to their pre-run baseline? Server state that stays after the client releases everything and the hosts unload is a finding (inherent retention), not a client failure |

ST-1 and ST-3 also produce the noise estimates for the detection limits (§5.5). ST-1 runs once on every OS that gets accelerated arms.

## 3. Workload

### 3.1 Query catalog

Per-hour counts are at k = 1 (production rate). The provider/repository column matters for attribution: repository queries are served by Winmgmt alone, provider queries by a WmiPrvSE host.

| Key | Namespace | WQL (as Esinta, unless noted) | /h at k=1 | Served by | Arrays | Ground truth (§6.6) |
|---|---|---|---|---|---|---|
| `proc_pid` | cimv2 | `QueryProcessByPID` with a PID from the latest truth snapshot (95 % live, 5 % recently exited = negative control) | 300 | provider | no | `OpenProcess`+`GetProcessTimes` before/after: alive throughout → exactly 1 row with matching `CreationDate`; exited → 0 |
| `proc_all` | cimv2 | `SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate FROM Win32_Process` (Esinta-style; added as large-set truth check) | 12 | provider | no | `NtQuerySystemInformation(SystemProcessInformation)` before/after |
| `svc` | cimv2 | `queryServices` (`services` collector) | 30 | provider | no | SCM `EnumServicesStatusEx` (Win32) before/after |
| `drv` | cimv2 | `queryDrivers` | 30 | provider | no | SCM `EnumServicesStatusEx` (driver) before/after |
| `evtlog` | cimv2 | Esinta `queryClearFmt` shape, bounded to the last 2 min of the Application log | 30 | provider | yes (`InsertionStrings`) | `wevtapi` `EvtQuery` count for the same window. **Excluded from the primary latency composite**: cost grows with log size (threat T10) |
| `ns_ctl` | cimv2 | `SELECT Name FROM __NAMESPACE` (**probe-only control**) | 12 | repository | no | invariant vs t0 |
| `fw_rules` | StandardCimv2 | `queryRules` (12 properties; `Profiles` and `EnforcementStatus` arrays where present) | 12 | provider | yes | invariant vs t0, cross-checked with the registry `FirewallPolicy\FirewallRules` value count |
| `fw_port` | StandardCimv2 | `queryPortFilters` (`LocalPort`, `RemotePort` string[]) | 12 | provider | yes | invariant vs t0 |
| `fw_app` | StandardCimv2 | `queryAppFilters` | 12 | provider | no | invariant vs t0 |
| `fw_addr` | StandardCimv2 | `queryAddrFilters` (`LocalAddress`, `RemoteAddress` string[]) | 12 | provider | yes | invariant vs t0 |
| `def_status` | Defender | `SELECT * FROM MSFT_MpComputerStatus` | 30 | provider | some | exactly 1 row; signature version logged |
| `def_pref` | Defender | `SELECT * FROM MSFT_MpPreference` | 30 | provider | yes (many, often NULL by default) | exactly 1 row; array values = t0 |
| `sub_*` (5) | subscription | the five `wmisubscriptions` queries | 60 | repository (filters, bindings) / provider-backed consumer classes | no | invariant vs t0 (count + names). If the namespace is empty on the clean VM, empty is a legitimate answer: either accept that and lose silent-empty detection here, or add inert fixture filters (host change, §8) |
| `task`, `task_info` | TaskScheduler | the two `scheduledtasks` queries | 24 | provider | no | invariant vs t0, cross-checked with the registry `TaskCache\Tasks` subkey count |
| hostposture (3) | DeviceGuard / VolumeEncryption / Tpm | as Esinta | 12 each | provider | no | only if the namespace exists on the VM (pre-flight). Otherwise left out: a `ConnectServer` failure every cycle is noise, not load |

The **array dose is measured, not assumed.** Each query row counts the `VT_ARRAY` values it actually read and their elements. Phase 3 checks before Stage 2 that the actual mix has the intended dose. If `MSFT_MpPreference` arrays are all NULL on a default VM, the dose comes from the firewall filters and `evtlog`.

### 3.2 Acceleration factor k

- **One knob:** every query's rate is k × its production rate (§3.1). The production *mix* is kept, so the accelerated workload has the same shape as production (external validity), just more of it.
- **k_H** (the fast arm) is the largest k that keeps probe-induced CPU ≤ 40 % of the VM's CPU capacity. Probe-induced CPU = probe + attributed WmiPrvSE + Winmgmt host. That leaves margin below the 50 % cap in §9.
  - It is set by a calibration ramp in pre-flight: k = 1, 5, 10, 20, 50, 100, 10 min each.
  - Expected k_H is about 30–100. At k = 1 the whole Esinta agent used 0.84–0.90 % of a core on the Win10 VM. The firewall queries (2.8 s CPU per cycle on the laptop post-#118) are the expensive part.
  - **The plan below assumes k_H = 50.**
  - **If calibration gives k_H < 10, acceleration is too weak to be worth it.** The design then becomes the long-run plan (L plus the strategy arms at k = 1), and we say so at that checkpoint.
- **k_M = k_H / 10** (the mid arm). **k_L = 1** (production rate).
- The schedule is deterministic: a fixed-seed order per arm, with per-query timers at their own rate, so the mix is the same in every hour. Rates never change inside an arm. There is no adaptive throttling, because throttling would confound rate with time. An arm that breaches a limit is aborted (§9).

### 3.3 Connection topology

The same topology is used in every correct-client arm except E3:
- **cimv2:** 3 fixed connections, each with its own worker. Queries are assigned round-robin. Esinta runs 3 worker tasks, and its pool usually holds 2–3 cimv2 connections.
- **Every other namespace:** 1 fixed connection, 1 worker.
- Total: 3 + (number of namespaces present − 1) connections, about 7–9.
- Each connection is serial (one call at a time), as in Esinta.
- E3 replaces the fixed connections with the Esinta pool and per-namespace recycled connections, fed by the same 3 workers. So concurrency is the same in every strategy arm.

**Count per connection at k_H = 50 over 72 h:**
- cimv2: about 505k per connection, about 200× the production maximum;
- Defender and subscription: about 216k each, about 600×;
- StandardCimv2: about 173k;
- TaskScheduler: about 86k.

## 4. Arms and run matrix

### 4.1 Arms

Client class `correct` = §2. Client class `buggy` = deliberately broken, analysed separately and stored under `results/<host>/buggy-<arm>/`. The analysis code refuses to pool the two classes (metadata field `client_class`).

| Arm | Class | Strategy | Workload, k | Duration | Purpose | Claims |
|---|---|---|---|---|---|---|
| **PF** pre-flight | – | – | idle, then calibration ramp | ~4 h per host | Isolation baseline, attribution map, provider-host unload timing, quotas, k_H, truth calibration (§8) | – |
| **ST-1** | correct | none | production mix, k_H | 6 h | Client cleanliness gate | gate |
| **ST-2** | buggy | none | production mix, k_H/10 | 1 h | Positive control: the gate detects #115 | gate, D |
| **ST-3** | correct | – | idle after ST-1 | 1 h | Release test | gate, C |
| **H** | correct | none | production mix, k_H (50) | **72 h** | Fast screen: does a correct client degrade at all? cimv2 ~1.5M queries | A, B, C |
| **X** | correct | none | stress mix: 16 cimv2 connections; array and large-result queries ×5 weight; same CPU budget | **48 h** | Stronger screen with every accelerator in the brief at once (concurrency, arrays, large sets, all namespaces). Not production-shaped; reported as such | A (stress), C |
| **M** | correct | none | production mix, k_H/10 (5) | **7 days** | Rate-scaling partner of H: matched count up to ~118k queries per cimv2 connection (~353k cimv2 in total), at 10× the age. H reaches that count at ~17 h. **Run only if H or X shows an effect** (§4.2) | B |
| **L** | correct | none | production mix, k = 1 | **21 days** (min 14) | Wall-clock arm: production rate, no refresh, 84× the production age limit. The only evidence for time-driven mechanisms | A, B |
| **E0** | correct | none | production mix, k_H | 72 h | = H. Reused if run in the same calendar window as E1–E3, rerun otherwise | E |
| **E1** | correct | timed: reconnect every 1 h | production mix, k_H | 72 h | Fixed-interval refresh | E, B (which clock) |
| **E2** | correct | adaptive: reconnect on a connection-level error (RPC disconnect / server unavailable, `WBEM_E_TRANSPORT_FAILURE`, `WBEM_E_SHUTTING_DOWN`, …), on deadline abandonment, or on an *impossible empty* (0 rows from `proc_all`, `svc`, `def_status`) | production mix, k_H | 72 h | Error-triggered refresh. The error list is fixed in pre-registration | E |
| **E3** | correct | pool-equivalent (Esinta: 6 h / 50k, health 30 s, replace unhealthy, abandon at deadline) | production mix, k_H | 72 h | The production mitigation. At k_H = 50 a cimv2 pool connection reaches 50k queries after about 7 h, so the 6 h age limit still triggers first, as in production. If calibration gives k_H > 60, the count limit triggers first, and the results say so | E |
| E-fault (optional) | correct | each of E0–E3 | as the arm | inside the 72 h | At t = 48 h, kill the attributed WmiPrvSE; at t = 60 h, restart Winmgmt. Recovery only, analysed separately from the degradation windows | E (recovery) |
| **B1** | buggy | none | production mix at 2 doses (k_H/10 and k_H/40: about 30 and 8 MB/h at #115's rate) | 2 × 4 h | #115 dose-response on Server 2016: leak per array read | D |
| **B2** | buggy | none | production mix, k_H; objects created and used from MTA threads (pre-#118), with 1 and 5 concurrent connections | 2 × 4 h | Cross-apartment cost on this OS: CPU per query, latency, abandoned calls | D |
| B3 (optional) | buggy | none | production mix; go-ole `ForEach` instead of the strict loop | 6 h | Only if H/X show S3 events: measures how many errors the library turns into silent results. Otherwise S3 counts from the correct arms suffice | D, C |
| X-raw (conditional) | correct | none | H's mix through native `IWbemLocator`/`IWbemServices` (no wbemdisp) | 72 h | Only if H shows an effect: is it in WMI or in the scripting layer? | A (scope) |
| SUB (deferred) | correct | none | long-lived `ExecNotificationQuery` on `Win32_ProcessStartTrace` + process churn | – | Another surface (event delivery; relates to the Win11 05-14 candidate). Separate design if wanted | – |

### 4.2 Stages and decision points

```
PF (each host) ──► ST-1 / ST-2 / ST-3 ──► gate report to the user (mini-checkpoint) ──► if pass:
   host A: L (21 d) ─────────────────────────────────────────────────────────────► end
   host B: H (72 h) ─► X (48 h) ─► analysis ─┬─ effect in H or X: M (7 d) ─► E1–E3 ─► B1/B2
                                             └─ no effect:          E1–E3 ─► B1/B2
```

- The gate failing stops everything: fix the client, rerun ST.
- The ST mini-checkpoint exists because L ties up a VM for three weeks. It isn't worth starting L with a client that hasn't passed.
- "Effect" means the pre-registered rule in §5 says *present* for at least one primary metric.

### 4.3 Run budget

**Hosts available today: none clean.**
- `win` (Win10 .155): runs the Esinta agent; busy soaking until 2026-10-19 ~20:00Z.
- `win2` (Server 2019 OT .126): runs the agent.
- Server 2016: needs a new target.
- Probe arms need dedicated **clones with no Esinta agent**. Ideally they come from one prepared snapshot (§8).

**Plan A: 2 Server 2016 clones (minimum)**

| Day | Host A | Host B |
|---|---|---|
| 0 | PF, ST-1 + ST-3 (7 h) | PF, ST-1 replicate + ST-3, ST-2 (8 h) |
| 0–1 | gate report, wait for OK | gate report, wait for OK |
| 1–22 | **L** (21 d) | H (3 d) → X (2 d) → [M (7 d) if effect] → E1, E2, E3 (3 × 3 d, sequential, snapshot revert between) → B1, B2 (1 d) |
| End | day ~22 | day ~16 (null) or ~23 (effect) |

**Plan B: 4 clones (recommended)**
- Host A: L.
- Host B: H → X → M.
- Hosts C and D: E1–E3 and an E0 rerun, in parallel with H, so strategies share a calendar window.
- B1/B2, and a second H replicate if there is an effect, fit before L ends.
- Same ~3-week end date, but with replication and no calendar confound between strategy arms.

**Cross-OS (F):** each additional OS (Server 2022, Win10, Win11) costs one clone for about 4 days (PF, ST-1/3, H). They can run in parallel. Without them, F stays at "no data", and the paper says so.

**Disk per arm** (`queries.csv`, about 350 B per row): at k_H = 50, about 9 queries/s, which is about 270 MB/day raw and about 30–40 MB/day gzip with hourly rotation. A 21-day L arm is about 115 MB raw. Budget 5 GB free per host. The abort threshold is 5 GB (§9).

## 5. How acceleration validity is checked (age vs count)

### 5.1 Three clocks

Each metric is tied to the scope of the state that could degrade:

| Clock | Count variable | Age variable | Reset by |
|---|---|---|---|
| Connection | `conn_query_n`, `conn_objects_n` | `conn_age_s` | reconnect (E1–E3) |
| Provider host (WmiPrvSE PID) | queries served by classes attributed to that host since its start | host process age | WMI unloading or killing the host (idle unload, quota), fault injection |
| Service (Winmgmt) | all probe queries since boot | time since boot | reboot / snapshot revert only |

- Latency and errors are analysed per connection and per query key.
- WmiPrvSE metrics are analysed per host lifetime, as segments split at PID changes.
- Winmgmt metrics are analysed per service lifetime.

The strategy arms then show which clock an effect follows. **If an effect survives hourly reconnects (E1), it does not live on the connection, and connection recycling is the wrong mitigation for it.**

### 5.2 Primary metrics (pre-registered)

| Metric | Unit |
|---|---|
| **P1** latency | log of the per-window median latency per query key, relative to the key's warm-up baseline, averaged over keys (excluding `evtlog`). p99 is analysed alongside |
| **P2** attributed WmiPrvSE private bytes | sum over the hosts attributed to the probe's classes, per host-lifetime segment |
| **P3** Winmgmt host | private bytes and handles |
| **P4** error rate | queries with a final non-success status, per 100k queries |
| **P5** silent-failure rate | S1–S5 (§6.6), per 100k queries |

**Secondary metrics:** WmiPrvSE handles and threads, WmiPrvSE restarts and their cause, `ConnectServer` latency, CPU per query, abandoned calls.
**Validity metrics, not outcomes:** client private bytes and handles, invariants, canary, foreign WMI operations.

All primary metrics are aggregated in **15-min windows**. Warm-up is the first 30 min or the first 5k queries per connection, whichever is later.

### 5.3 Decision rule (stated before any data)

**Step 0: is the arm valid?**
- ST passed on that host.
- Invariant violations = 0.
- Foreign WMI operations under the limit in ≥ 90 % of monitored windows (§7).
- Canary within ±20 % of its baseline in ≥ 95 % of windows.
- No abort.
- An invalid arm is reported as invalid and not analysed for A–C.

**Step 1: is there an effect? (arm H, then X)** For each primary metric, test the slope against its smallest effect of interest (SESOI, §5.5):

| Outcome | Condition |
|---|---|
| Present | 90 % CI of the slope excludes 0 **and** the point estimate ≥ SESOI |
| Absent | Equivalence (TOST): the 90 % CI lies entirely within ±SESOI |
| Inconclusive | Anything else; H is extended by 72 h once, then reported as inconclusive |

Holm correction across P1–P5. Standard errors: Newey–West (HAC) on window aggregates, plus a block bootstrap with 1 h blocks as a check.

**Step 2: count or time? (only for metrics that are present; arms H, M, L)**
- Let Δ_arm(n) and Δ_arm(t) be the effect curves (window value minus warm-up baseline) against count and against age on the metric's clock. H runs at 10× M's rate.
- **Count-collapse ratio** ρ_n = Δ_M(n\*) / Δ_H(n\*), at n\* = the largest count M reaches, and at ¼, ½ and ¾ of it.
- **Time-collapse ratio** ρ_t = Δ_M(t\*) / Δ_H(t\*), at t\* = H's duration.
- Expected values: pure count-driven gives ρ_n ≈ 1, ρ_t ≈ 0.1. Pure time-driven gives ρ_t ≈ 1, ρ_n ≈ 10 (if linear).

| Verdict | Condition (90 % bootstrap CIs) | What it means for acceleration |
|---|---|---|
| **Count-driven** | ρ_n within [0.5, 2] at every n\* point **and** ρ_t upper bound < 0.5 | **Valid.** Accelerated results project to production by count, only within the count range covered by ≥ 2 rate arms. No extrapolation beyond it |
| **Time-driven** | ρ_t within [0.5, 2] **and** ρ_n lower bound > 2 | **Not valid.** H/M/X say nothing about this metric over time. Arm L is the evidence, bounded by its duration |
| **Mixed** | Joint fit Y = a_arm + b·n + c·t on H, M, L (n and t are decorrelated across the 50× rate span): b and c both significant, each ≥ 25 % of the predicted effect at production rate over 30 days | Partly valid. Both coefficients reported; production projection uses both |
| **Load-dependent** | Neither collapse holds, e.g. ρ_n < 0.5: more effect per query at high rate | **Not aging.** Reported as a load effect with the rate at which it appears; not used for claim A |
| **Undetermined** | The effect appears only beyond the count that M reaches | Said plainly; M is extended if the calendar allows |

- Linear endpoints can mislead if the effect has a threshold. As a secondary check, we compare whole curves: the RMS distance between the H and M curves plotted against n, versus against t (block bootstrap). If the two checks disagree, the verdict is "undetermined".

**Step 3: which clock?** Compare E1/E3 with E0 for each present effect:
- If it resets at reconnect → connection clock.
- If it resets at a WmiPrvSE PID change (natural or E-fault) → provider-host clock.
- Otherwise → service clock.

**If nothing is present** (step 1 absent or inconclusive everywhere), M is skipped, and the results are stated as bounds:
- "no effect ≥ SESOI through n queries per connection (Y× production) in 72 h at k_H";
- "no effect ≥ SESOI over 21 days at production rate (L)".
- Claim B is then answered as "neither count up to N nor age up to T produces an effect", with no attribution to either.

### 5.4 Regime checks: is the fast arm the same system?

High rate is only a faster clock if the system stays in the same regime. These checks run in every rate arm and are reported:
- **Provider-host lifecycle.** WMI unloads idle provider hosts, so at low rates a host may exit between queries and restart clean. That is a free refresh the fast arm never gets.
  - PF measures the idle-unload time per hosting model empirically and reads the `__CacheControl` settings.
  - Every arm logs host PID lifetimes.
  - If L's hosts unload between queries (likely for namespaces queried only every 1–2 min), L is compared with H **per host-lifetime segment**, never as one series. This is also how production behaves, which is worth saying in the paper.
- **WMI quotas.** WMI kills a provider host that exceeds its quota: the documented defaults are 512 MB private per host, 4,096 handles per host, 256 threads, and 1 GB across all hosts. PF reads the actual `__ProviderHostQuotaConfiguration`.
  - Quota events are recorded: WMI-Activity events, a PID change right after growth, and `WBEM_E_QUOTA_VIOLATION` on our queries.
  - Quota events are outcomes (a self-healing signature), not aborts.
  - They reset the host clock, which step 2 must account for.
- **CPU contention.** Probe-induced CPU stays ≤ 40 %, and a non-WMI canary (a fixed hashing loop timed every 10 s) detects contention from the host or hypervisor.
  - If latency degradation in H coincides with canary degradation, it is contention.
  - The P1 comparison is also done on CPU-normalized latency: latency / canary.
- **Result-set drift.** Rows per query are logged. Latency is also analysed per row, because process, service, rule and event-log counts change over time.

### 5.5 Thresholds and pre-registration

- **Before Stage 2**, Phase 3 commits `docs/preregistration.md`. It holds: the SESOI values below (after your review), the minimum detectable effect (MDE) computed from ST-1 noise, warm-up, window size, the decision rule above, k values, the adaptive error list, and the analysis code commit.
- **If MDE > SESOI for a metric**, H's duration grows until MDE ≤ SESOI, or we report that the metric can't be resolved.
- Any analysis not pre-registered is labeled exploratory.

**Proposed SESOI** (you decide; these define what "degradation" means in the paper):

| Metric | SESOI per 1M queries on the clock | SESOI per day | Rationale |
|---|---|---|---|
| P1 latency (median) | +20 % | +5 %/day | A 20 % slowdown is about the run-to-run spread between Esinta builds (p90 177–273 ms) |
| P1 latency (p99) | +100 % | +25 %/day | Tail matters for deadlines (500 ms enrichment) |
| P2 attributed WmiPrvSE private bytes | +10 MB | +2 MB/day | 10 MB per 1M queries ≈ 60 MB/year at the VM's production rate |
| P3 Winmgmt private bytes | +5 MB | +1 MB/day | Winmgmt has no quota; its growth affects every WMI client |
| P3 Winmgmt handles | +100 | +20/day | |
| P4 / P5 error and silent rates | +1 per 100k queries over warm-up | same | The VM saw 0 WBEM errors in its retained logs |

## 6. Instrumentation and output schema

### 6.1 Files

All files go in `results/<host>/<arm>/<run_id>/`. CSVs rotate hourly and are gzipped when closed. Timestamps are UTC, RFC 3339 with nanoseconds. Latency comes from Go's monotonic clock.

| File | Rows |
|---|---|
| `queries.csv` | one per query (§6.2) |
| `connections.csv` | one per connection lifecycle event (§6.3) |
| `procs.csv` | every 10 s, one per tracked process (§6.4) |
| `host.csv` | every 10 s: host resources, canary, and every counter (§6.5) |
| `events.csv` | WMI-Activity events, provider-host starts and exits, aborts, fault injections, Defender signature changes |
| `truth.csv` | per-query ground-truth details when there is a mismatch: missing and phantom keys |
| `meta.json` | probe commit, Go version, every flag, k, catalog hash, `client_class`, OS build and UBR, hostname, IP, VM spec, PF reference, start/end UTC, end reason |
| `preflight.json` | the PF outputs (§8) |

**The sampler never uses WMI.** The old probe sampled WmiPrvSE through WMI, on a connection that was itself under test. Probe v2 uses:
- `NtQuerySystemInformation(SystemProcessInformation)`: one call gives PID, create time, private bytes, working set, handles, threads and CPU times for every process;
- `GetProcessMemoryInfo` and `GetProcessHandleCount` for the probe itself;
- SCM `QueryServiceStatusEx` for the Winmgmt PID;
- `EnumProcessModulesEx` for the provider DLLs loaded in each WmiPrvSE;
- `GetSystemTimes` and `GlobalMemoryStatusEx` for the host.

### 6.2 `queries.csv`

| Columns | Meaning |
|---|---|
| `run_id, arm, query_seq` | Global monotonic **query ID** |
| `ts_start` | UTC start |
| `conn_id, conn_slot, conn_gen` | **Connection ID** (UUID), its slot (e.g. `cimv2#2`) and generation (reconnects in that slot) |
| `namespace, query_key, worker` | Catalog key (§3.1); the query text lives in `meta.json` by key |
| `conn_query_n, conn_objects_n, conn_age_s` | Count and age on the connection clock, including this query |
| `host_pid, host_query_n` | Attributed WmiPrvSE PID for this class at that moment, and the host clock count |
| `deadline_ms, latency_ms, exec_ms, first_row_ms, enum_ms` | Total latency, plus phases (`ExecQuery` return, first `Next`, full enumeration) |
| `rows, props_read, array_props_read, array_elems_read` | Size and array dose |
| `status` | `ok` / `error` / `abandoned` / `hung` / `overloaded` |
| `hr, scode, wcode, err_op, err_src, err_text` | Outer HRESULT, EXCEPINFO scode (the WBEM code), wCode; the operation that failed (`ExecQuery`, `Next`, `Properties_`, `GetProperty`, …); source; text truncated to 200 chars |
| `enum_end_hr` | HRESULT that ended the enumeration (`S_FALSE` expected) |
| `items_skipped, props_failed, panics` | Partial-result events (§2.2) |
| `sta_tid, apt_ok, ledger_outstanding, ledger_double` | Invariants (§2.3) |
| `truth_kind, truth_lo, truth_hi, truth_missing, truth_phantom, silent_mask` | Ground truth (§6.6) |

### 6.3 `connections.csv`

| Columns | Meaning |
|---|---|
| `run_id, arm, ts, conn_id, prev_conn_id, conn_slot, conn_gen, namespace` | Which connection |
| `event` | `sta_start` / `connect_ok` / `connect_fail` / `retire` / `close` / `release_done` |
| `reason` | `initial` / `timed` / `adaptive:<class>` / `age` / `count` / `unhealthy` / `abandoned` / `idle` / `shutdown` / `fault` |
| `sta_start_ms, connect_ms, security_ms` | Timings |
| `hr, scode, wcode, err_op, err_text` | **Full `ConnectServer`-path codes** |
| `queries_at_event, objects_at_event, age_s` | Connection clock at the event |

### 6.4 `procs.csv`

| Columns | Meaning |
|---|---|
| `ts, role` | Role: `probe` / `wmiprvse` / `winmgmt_host` / `foreign_wmi_client` (seen in the ETW meter) |
| `pid, create_time, image, account` | Process identity |
| `host_label` | For WmiPrvSE: account + provider DLL set (§7) |
| `private_bytes, working_set, handles, threads, cpu_kernel_ms, cpu_user_ms` | Resources |
| `go_heap_alloc, go_heap_sys, goroutines, num_gc` | Probe only |
| `services_in_host` | For the Winmgmt host: the services sharing that PID |

### 6.5 `host.csv`: periodic counters

| Columns | Meaning |
|---|---|
| `ts` | Timestamp |
| `cpu_total_pct, cpu_probe_induced_pct` | CPU |
| `avail_phys_mb, commit_mb, commit_limit_mb, disk_free_gb` | Memory and disk |
| `canary_us` | Contention canary |
| `queries_total, errors_total, silent_total{S1..S5}` | Outcome counters |
| `inflight, abandoned_total, overloaded_total, hung_total` | Call counters |
| `connects_total, connect_fail_total, recycles_total{reason}` | Connection counters |
| `wmiprvse_count, wmiprvse_restarts_total` | Provider hosts |
| `etw_window_on, foreign_wmi_ops` | Isolation meter |

### 6.6 Ground truth for silent failures

**Bracketing.** For classes with a non-WMI source, take a truth snapshot immediately before and after the WMI query:
- A key present in both snapshots, with the same create time, must appear in the result.
- A key in neither snapshot, and not started during the query, must not appear.

**Invariants.** For classes that are static on an isolated VM, the expected answer is the t0 answer (captured in PF), cross-checked with the registry where possible. Any change is flagged. It counts as silent only when the non-WMI cross-check is unchanged.

| Class | Definition |
|---|---|
| **S1 impossible-empty** | 0 rows where truth or the invariant requires ≥ 1 (`proc_pid` for a live PID, `proc_all`, `svc`, `def_*`, `fw_*`) |
| **S2 truncated** | rows < truth lower bound (a bracketed key is missing) |
| **S3 error-terminated enumeration** | `enum_end_hr` not `S_FALSE`, whatever the rows. **go-ole `ForEach` would report this as success** |
| **S4 partial objects** | `items_skipped > 0` or `props_failed > 0` (Esinta drops these silently) |
| **S5 content mismatch** | phantom keys (a PID in neither snapshot, nor started during the query), or a key property that differs from truth (`CreationDate`) |

- **`proc_pid` resolves an open question from the inventory.** On the VM, 26–70 % of Esinta's `GetProcessByPID` calls were empty, which can't be split into "process exited" and "silent empty" without ground truth. Bracketing a live PID gives exactly that split.
- **Truth itself has a measured error rate.** PF runs the truth comparison during idle time and at k = 1 to find the baseline mismatch rate per class, from race windows and known always-different PIDs such as `Secure System` and `Registry`. That baseline is subtracted and its CI reported.

### 6.7 Mapping from the old probe schema

| Old column (`reference/old-probe/internal/metrics/recorder.go`) | Problem | v2 replacement |
|---|---|---|
| `query_latency_ms` | One value per 10 s sample: the last query only; distribution lost | `queries.csv` `latency_ms` and phases, one row per query |
| `error_code` / `error_message` | Last error only; outer HRESULT | Per query: `hr`, `scode`, `wcode`, `err_op` |
| `wmiprvse_memory_bytes` / `_handles` / `_pagefile_bytes` / `_threads` | Summed over all WmiPrvSE, measured **through WMI**, working set | `procs.csv` per PID via NtQSI: private bytes, handles, threads, CPU, plus attribution |
| `winmgmt_*` | Through WMI (`Win32_Service` + `Win32_Process`) | `procs.csv` `role=winmgmt_host` via SCM; `services_in_host` |
| `connection_age_seconds`, `refresh_count`, `oldest_conn_age_seconds` | No connection ID | `conn_id`, `conn_gen`, `conn_age_s` per query; `connections.csv` |
| `process_count` | No truth | `rows` + truth columns |
| – | Not recorded | Client private bytes and handles, invariants, silent classes, in-flight / abandoned counters, foreign WMI operations, canary |

The old probe's other columns (subscription and pool modes) have no v2 equivalent until the deferred SUB arm.

## 7. Attribution: WmiPrvSE and Winmgmt

- **Static map (PF):** for each class in the catalog, find its provider (`__Win32Provider` via the class `provider` qualifier) and the provider's `HostingModel`.
  - This is read once on a separate short-lived connection before the arm starts, and recorded in `preflight.json`.
  - Repository-only classes (`__NAMESPACE`, `__EventFilter`, `__FilterToConsumerBinding`) have no provider host. They load Winmgmt only, which makes them a useful contrast.
- **Dynamic map (every sample):** each WmiPrvSE gets a `host_label` from its account and the set of provider DLLs it has loaded (`EnumProcessModulesEx`). The host that has class X's provider DLL loaded serves X.
  - WMI-Activity/Operational event 5857 (provider started: provider name, host PID) is read with `wevtapi`, not WMI, as a cross-check.
- **Synchronisation check (PF):** in the calibration ramp, the CPU time of an attributed host must rise with the rate of its classes, and unattributed hosts must not.
- **Winmgmt:** PID from SCM.
  - On Server 2016 (build 14393, which predates svchost splitting in 1703), Winmgmt shares a `netsvcs` svchost with many other services, so its process metrics would be contaminated.
  - **Proposal:** run `winmgmt /standalonehost` on the probe clones so Winmgmt has its own svchost. That is a host change (§8). One replicate in the default shared host checks that it doesn't change the results.
  - `services_in_host` in `procs.csv` verifies the isolation on every sample.
- **Foreign WMI clients:**
  - A real-time ETW session on Microsoft-Windows-WMI-Activity counts operations by `ClientProcessId`, excluding the probe.
  - It is **duty-cycled at 60 s on / 14 min off**, because tracing every one of our own operations adds load. ST-1 measures its overhead, on vs off.
  - Limit: ≤ 60 foreign operations per hour per window. Windows over the limit are flagged, and the arm is invalid if more than 10 % are flagged.

## 8. Host isolation and preparation

None of this happens before you approve Phase 3, and before you confirm each VM's hostname/IP and that it is idle.

**Proposed prepared snapshot** (each clone reverts to it before every arm):
1. Clean Server 2016 install, patched to a recorded UBR. **No Esinta agent**, no monitoring agents, no SCCM. List every installed service.
2. Windows Update paused for the campaign. Defender left on (its namespace is in the catalog); signature updates are logged, not blocked.
3. Server Manager auto-start at logon disabled; it polls WMI.
4. `winmgmt /standalonehost` (§7).
5. Fixed memory with no ballooning. Proxmox node co-tenants recorded.
6. The probe runs as **LocalSystem** (the same as Esinta), via a one-shot scheduled task. No service install. Results go to `C:\probe\results\`, pulled with `lab_ssh.py get`.
7. Optional, only if `root\subscription` is empty by default: three inert `__EventFilter` fixtures with no consumers and no bindings, giving `sub_*` a known non-empty answer.

**Pre-flight PF** (about 4 h per host, before the first arm):
- 60 min idle baseline: foreign WMI operations, the WmiPrvSE inventory, Winmgmt host services.
- Static attribution map.
- Quotas and `__CacheControl` settings.
- Empirical provider-host unload time: query each class once, then watch PIDs for 30 min.
- Truth calibration (§6.6).
- k_H calibration ramp (§3.2).
- H-enum check: one invalid-class query, to confirm or refute the hypothesis in §2.2.

## 9. Safety: impact caps and abort thresholds

**Design caps.**
- Probe-induced CPU ≤ 40 % of capacity, set through k (§3.2).
- Probe memory: `GOMEMLIMIT=256MiB`.
- ≤ 16 in-flight calls.
- Fixed rate, never adaptive.

**Hard abort** (stop, close connections, write the final rows, `meta.json` end reason). Checked every 10 s; each condition must hold for 3 consecutive samples unless noted:

| Condition | Threshold |
|---|---|
| Host available physical memory | < 10 % or < 400 MB |
| Commit charge | > 90 % of the commit limit |
| Host total CPU | > 90 % for 10 min (sustained, not 3 samples) |
| Probe-induced CPU | > 50 % for 10 min |
| Results volume free space | < 5 GB |
| Winmgmt host private bytes | > 1 GB, or handles > 50,000 (no quota protects it; growth there degrades every WMI client) |
| WmiPrvSE instances | > 24 (the documented default `ProcessLimitAllHosts` is 32) |
| Probe | private bytes > 512 MB, handles > 10,000, goroutines > 10,000 |
| Single WMI call (strategy `none`) | `hung` recorded at 10 min; arm aborted at 60 min. **A hung connection is itself a result** |
| System event | unexpected reboot, bugcheck, or WMI repository corruption event → abort, arm invalid |

**Not aborts:** WmiPrvSE quota kills, WmiPrvSE restarts, query errors, silent failures. These are the outcomes being measured, and WMI handles them by design.

## 10. Threats to validity

**Internal**

| # | Threat | Mitigation |
|---|---|---|
| T1 | "Correct" means free of *known* bugs; an unknown client bug could still produce server-side growth (e.g. unreleased enumerators held by WMI) | Ledger, apartment assertions, ST-1/ST-2/ST-3; the release test separates client-held from inherent state; X-raw differential client if an effect appears |
| T2 | Observer effects: truth snapshots, module enumeration, ETW meter, CSV writes | Sampler does not use WMI; ETW duty-cycled; ST-1 measures overhead of each with on/off windows |
| T3 | Foreign WMI clients contaminate WmiPrvSE/Winmgmt | Isolation (§8), ETW meter, window and arm invalidation rule (§7) |
| T4 | Shared svchost on Server 2016 | `/standalonehost`; `services_in_host` check; one shared-host replicate |
| T5 | Provider hosts unload at low rate but never at high rate: different regimes | Measured in PF; host-lifetime segmentation; regime checks (§5.4) |
| T6 | WMI quotas silently reset provider hosts | Quota config recorded; PID-change and quota events; per-segment analysis |
| T7 | CPU contention at high rate is mistaken for degradation | 40 % budget; canary; CPU-normalized latency; matched-count comparison with M |
| T8 | Calendar confounders: updates, Defender signatures, scheduled tasks, diurnal patterns | Updates paused; events logged; 72 h arms span 3 diurnal cycles; parallel clones in plan B; snapshot revert per arm |
| T9 | Hypervisor noise: Proxmox co-tenants, KSM, ballooning | Fixed memory, recorded co-tenants, canary |
| T10 | Result sets drift: event log growth, process count, rules; cost per query changes for reasons unrelated to WMI | `rows` logged; per-row latency; `evtlog` left out of P1 composite; log size recorded |
| T11 | Hypothesis H-enum (§2.2) wrong: wbemdisp may report errors at `ExecQuery` after all | Checked in PF before any arm; S3 counted either way |

**Construct**

| # | Threat | Mitigation |
|---|---|---|
| T12 | "Degradation" = P1–P5; other forms (subscription delivery loss, remote DCOM) not covered | Stated scope; SUB arm deferred; all connections local |
| T13 | Ground truth has races | Bracketing; measured baseline mismatch per class, subtracted with CI |
| T14 | wbemdisp scripting path only; System.Management (`Get-WmiObject`) and MI/WMIv2 (`Get-CimInstance`) clients not tested | Stated; X-raw (native `IWbemServices`) if an effect appears |

**External**

| # | Threat | Mitigation |
|---|---|---|
| T15 | Server 2016 VMs only; virtualized; not OT hardware | Cross-OS arms if clones exist; otherwise F reported as untested |
| T16 | Production mix from one Win10 VM's Esinta rates; the OT host runs about 3.6× less cimv2 load | k is relative to the VM mix; OT rates reported for scale |
| T17 | Clean lab VMs vs real hosts with SCCM and monitoring agents contending for WmiPrvSE | A null result covers uncontended hosts only; stated in the paper |

**Statistical**

| # | Threat | Mitigation |
|---|---|---|
| T18 | One host per arm, autocorrelated series, several metrics | HAC errors, block bootstrap, Holm; replicate H (plan B) and any positive arm before claiming it |
| T19 | Forking paths after seeing data | Pre-registration (§5.5); everything else labeled exploratory |
| T20 | Extrapolation beyond the observed count or age | Forbidden by the decision rule; projections only inside the range covered by ≥ 2 arms |

## 11. What Phase 3 would build (outline only)

**Code:** `cmd/probe2` plus these packages:
- `sta` (thread + anchor, from §2.1);
- `wmiconn` (connection, strict enumerator, ledger, full error capture);
- `strategy` (none / timed / adaptive / pool);
- `catalog`;
- `truth`;
- `sampler` (NtQSI, SCM, modules, ETW meter, canary);
- `csvout`;
- `buggy` (B1/B2 behind an explicit `-client-class=buggy` flag; refuses to write to a non-`buggy-` directory).

**Testing:**
- Unit tests use fakes.
- Windows integration tests sit behind a build tag. They **don't run on the dev laptop before 2026-10-19 ~20:00Z**, because they would contaminate the soak's WmiPrvSE metrics.
- `gofmt` before commits.

**Analysis** (`analysis/`, Python venv) produces:
- latency vs connection age and vs count, per arm;
- attributed WmiPrvSE/Winmgmt trajectories with host-lifetime segments;
- error and silent-failure rates by strategy;
- the collapse plots and ρ estimates (§5.3);
- the #115/#118 before/after figures from the Phase 1 data.

## 11a. Implementation notes (2026-10-16, branch `feature/probe-v2`)

The first implementation is in `probe/` (see its README). It differs from, or adds to, this design in these places:

**Catalog (§3.1)**
- The two cimv2 event-log queries are Esinta's own `eventlogconfig` queries: Security 1102 and System 104, newer than now − 2 min, 30/h each, so 60/h in total.
- That leaves 276/h for `proc_pid` (cimv2 still sums to 420/h).
- Both event-log queries have truth kind `none` until the `wevtapi` cross-check exists.

**Timing**
- Every duration comes from QueryPerformanceCounter. Go's monotonic clock on Windows advanced in ~0.5 ms steps on the dev laptop, and can be coarser on other hosts.

**Invariant truth (§6.6)**
- A changed answer is flagged S2/S5 on every row.
- After `RebaselineAfter` = 3 identical changed answers, the baseline moves and an `invariant_rebaseline` event is written. Analysis drops the flagged rows that precede a rebaseline: those were a real change, not a silent failure.

**E3 pool-equivalent**
- Age, count and idle limits are checked when the connection is about to be used. Esinta checks them every 30 s on idle connections. This differs only for connections idle at that moment.
- The unhealthy test copies Esinta's `shouldMarkUnhealthy(mapWindowsError(OleError.Code()))`. It uses the *outer* HRESULT, so errors wrapped in `DISP_E_EXCEPTION` never match. **Esinta's error-based health marking probably almost never fires**; that is to confirm with data.

**Additional Esinta findings from reading the code (not touched)**
- The WBEM constant table in `errors.go` is shifted by one from `0x8004100D` on. For example, it defines `WBEM_E_INVALID_NAMESPACE` as `0x8004100D`; the value in `wbemcli.h` is `0x8004100E`.
- `setSecurity` sets `AuthenticationLevel = 3`, and the code calls it "Packet". For `SWbemSecurity`, 3 is `wbemAuthenticationLevelCall`. The probe copies the value so that it matches production.

**Isolation**
- `probe2` refuses to start when a known WMI-heavy service or process is running, such as `EsintaEndpoints` or Server Manager, unless `-allow-foreign-wmi` is passed. The override is recorded in `meta.json` `args`.

**Task Scheduler defaults (found on win2, 2026-10-17)**
- A task made with `schtasks /Create /TR` runs at task priority 7, and the probe process was **BelowNormal**. Such a task also has the default 72 h `ExecutionTimeLimit`, which would kill H at its end and M and L partway through.
- `tools/probe_task.py` now creates tasks from XML (priority 4, `ExecutionTimeLimit PT0S`, no battery conditions). `probe2` also raises itself to NORMAL and records `priority_class` (as started, and whether it was raised) in `meta.json` and `preflight.json`.
- The first pre-flight (`20261017T191458Z`) ran BelowNormal from the old binary. Only its k calibration ramp is affected, and only under CPU contention.

**H-enum confirmed on Server 2019 (win2, 2026-10-17 19:14Z, `wmi-integration.test.exe`, one query)**
- `SELECT * FROM Win32_NoSuchClass_Probe2` with `ReturnImmediately|ForwardOnly`: `ExecQuery` **succeeded**. The error surfaced at the first `Objects.Next` as `WBEM_E_INVALID_CLASS` (0x80041010) after 0 items.
- The same query through go-ole `oleutil.ForEach` returned **no error and 0 items**: an empty success.
- Esinta uses these flags (`connection.go:518`) and `oleutil.ForEach` for both objects and properties (`connection.go:542`, `:589`). An enumeration-time error in Esinta is therefore reported as an empty result, not an error.
- Scope: this is shown only for an invalid class (one query, one host). Whether access-denied, provider-failure or quota errors also surface at `Next` is untested; E-fault would test it.

**Not yet built (increment 2)**
- ETW foreign-client meter;
- event 5857 attribution cross-check;
- `wevtapi` truth;
- E-fault;
- X-raw client;
- analysis scripts.

## 12. Decisions needed from you

1. **Clones:** how many clean Server 2016 clones can you provide (plan A: 2, plan B: 4)? Their vCPU and RAM (4 vCPU / 8 GB suggested)? Can each revert to a prepared snapshot between arms? Any Server 2022 / Win10 / Win11 clones for F?
2. **Host preparation (§8):** OK to pause updates, disable Server Manager auto-start, use `winmgmt /standalonehost`, run as LocalSystem via a one-shot scheduled task, and possibly add inert `__EventFilter` fixtures?
3. **SESOI values (§5.5):** these define "degradation" for the paper. Accept them or adjust?
4. **L duration:** 21 days (recommended) or 14 days minimum?
5. **Optional arms:** E-fault, B3, X-raw (conditional), SUB (deferred). Which do you want in scope?
6. **The Esinta findings in §2.2** (`ForEach` dropping `Next` errors, silent item/property skips, outer HRESULT only): they affect the product. Do you want them raised there, separately from this project? Nothing in `esinta-endpoints` has been touched.

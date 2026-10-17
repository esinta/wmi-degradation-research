"""Self-test gate (design §2.4): ST-1 client no-growth, ST-2 positive control,
ST-3 release test. Criteria are the pre-stated ones; nothing here is tuned
on data.

    .venv/Scripts/python analysis/gate.py --st1 <run dir> [--st2 <run dir>] [--json out.json]

Slopes are OLS with Newey-West (HAC) standard errors on the 10 s samples,
maxlags = 90 samples (15 min); "upper CI" is the upper end of the two-sided
95 % interval.
"""

import argparse
import json
import sys

import numpy as np
import pandas as pd
import statsmodels.api as sm

from load import event_time, load_run

WARMUP = pd.Timedelta(minutes=30)
HAC_LAGS = 90
MB = 1024 * 1024

# Pre-stated thresholds (design §2.4).
PRIV_SLOPE_MB_H = 1.0
PRIV_B_PER_ARRAY_READ = 3.0
HANDLE_RANGE = 50
HANDLE_PER_1K = 1.0
RELEASE_MB = 5.0
# ST-2: "same order as #115 (~300 B per array read)" = within a factor of
# sqrt(10) either side.
ST2_LO, ST2_HI = 300 / 10 ** 0.5, 300 * 10 ** 0.5


def slope_ci(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    ok = np.isfinite(x) & np.isfinite(y)
    x, y = x[ok], y[ok]
    if len(x) < 30 or np.ptp(x) == 0:
        return dict(n=int(len(x)), slope=None, lo=None, hi=None)
    fit = sm.OLS(y, sm.add_constant(x)).fit(cov_type="HAC", cov_kwds={"maxlags": HAC_LAGS})
    lo, hi = fit.conf_int(0.05)[1]
    return dict(n=int(len(x)), slope=float(fit.params[1]), lo=float(lo), hi=float(hi))


def window(run):
    start = event_time(run, "arm_start") or run.procs["ts"].min()
    end = event_time(run, "release_test_start") or event_time(run, "arm_end") or run.procs["ts"].max()
    return start, start + WARMUP, end


def invariants(run):
    q = run.queries
    if q.empty:
        return {"queries": 0}
    return {
        "queries": int(len(q)),
        "apt_not_ok": int((q["apt_ok"].astype(str) != "true").sum()),
        "ledger_outstanding": int((q["ledger_outstanding"] > 0).sum()),
        "ledger_double": int((q["ledger_double"] > 0).sum()),
        "ledger_leaked": int((q["ledger_leaked"] > 0).sum()),
        "panics": int((q["panics"] > 0).sum()),
    }


def client_growth(run):
    """ST-1 measurements over [warm-up end, release/arm end]."""
    start, warm_end, end = window(run)
    p = run.procs[run.procs["role"] == "probe"].sort_values("ts")
    p = p[(p["ts"] >= warm_end) & (p["ts"] <= end)]
    hours = (p["ts"] - warm_end).dt.total_seconds() / 3600

    q = run.queries.sort_values("ts_start")
    cum = pd.DataFrame({"ts": q["ts_start"], "arrays": q["array_props_read"].cumsum(),
                        "queries": np.arange(1, len(q) + 1)})
    at = pd.merge_asof(p[["ts"]], cum, on="ts")
    in_win = q[(q["ts_start"] >= warm_end) & (q["ts_start"] <= end)]

    r = {
        "window": [str(warm_end), str(end)],
        "samples": int(len(p)),
        "queries_in_window": int(len(in_win)),
        "array_reads_in_window": int(in_win["array_props_read"].sum()),
        "private_mb_per_h": slope_ci(hours, p["private_bytes"] / MB),
        "private_b_per_array_read": slope_ci(at["arrays"], p["private_bytes"]),
        "handles_range": int(p["handles"].max() - p["handles"].min()) if len(p) else None,
        "handles_per_1k_queries": slope_ci(at["queries"] / 1000, p["handles"]),
        "threads_min_max": [int(p["threads"].min()), int(p["threads"].max())] if len(p) else None,
        "go_heap_mb_per_h": slope_ci(hours, p["go_heap_alloc"] / MB),
    }
    hi = lambda k: r[k]["hi"]
    checks = {
        "private_slope": hi("private_mb_per_h") is not None and hi("private_mb_per_h") < PRIV_SLOPE_MB_H,
        "private_per_array_read": hi("private_b_per_array_read") is not None and hi("private_b_per_array_read") < PRIV_B_PER_ARRAY_READ,
        "handles_range": r["handles_range"] is not None and r["handles_range"] <= HANDLE_RANGE,
        "handles_slope": hi("handles_per_1k_queries") is not None and hi("handles_per_1k_queries") < HANDLE_PER_1K,
        "go_heap_flat": hi("go_heap_mb_per_h") is not None and hi("go_heap_mb_per_h") < PRIV_SLOPE_MB_H,
    }
    r["checks"] = checks
    # "Threads constant" is reported for review, not auto-failed: the Go
    # runtime may add an M under blocking syscalls.
    r["threads_constant"] = r["threads_min_max"] is not None and r["threads_min_max"][0] == r["threads_min_max"][1]
    r["pass"] = all(checks.values())
    return r


def release(run):
    """ST-3: client private bytes after closing everything and idling."""
    rs, re_ = event_time(run, "release_test_start"), event_time(run, "release_test_end")
    if rs is None:
        return {"ran": False}
    _, warm_end, _ = window(run)
    p = run.procs[run.procs["role"] == "probe"].sort_values("ts")
    post_warm = p[(p["ts"] >= warm_end) & (p["ts"] < warm_end + pd.Timedelta(minutes=10))]["private_bytes"].median()
    end = re_ or p["ts"].max()
    tail = p[(p["ts"] > end - pd.Timedelta(minutes=10)) & (p["ts"] <= end)]["private_bytes"].median()
    r = {"ran": True, "post_warmup_mb": post_warm / MB, "release_end_mb": tail / MB,
         "delta_mb": (tail - post_warm) / MB, "pass": bool(tail - post_warm <= RELEASE_MB * MB)}

    # Measured, not gated: server-side state at the end vs the run's start.
    pr = run.procs
    first_ts, last_ts = pr["ts"].min(), pr[pr["ts"] <= end]["ts"].max()
    def snap(ts, role):
        s = pr[(pr["ts"] == ts) & (pr["role"] == role)]
        return {int(row.pid): {"private_mb": row.private_bytes / MB, "handles": int(row.handles), "label": row.host_label}
                for row in s.itertuples()}
    r["winmgmt_start"], r["winmgmt_end"] = snap(first_ts, "winmgmt_host"), snap(last_ts, "winmgmt_host")
    r["wmiprvse_start"], r["wmiprvse_end"] = snap(first_ts, "wmiprvse"), snap(last_ts, "wmiprvse")
    ev = run.events
    r["wmiprvse_exits_during_release"] = int(((ev["kind"] == "wmiprvse_exit") & (ev["ts"] >= rs) & (ev["ts"] <= end)).sum())
    return r


def fmt_ci(d, unit):
    if d["slope"] is None:
        return f"n/a (n={d['n']})"
    return f"{d['slope']:.4g} {unit} [95% CI {d['lo']:.4g}, {d['hi']:.4g}] (n={d['n']})"


def report(name, run, g):
    print(f"== {name}: {run.dir}")
    print(f"   arm {run.meta.get('arm')} class {run.meta.get('client_class')} bug {run.meta.get('bug', '-')} "
          f"k {run.meta.get('k')} commit {run.meta.get('probe_commit')} priority {run.meta.get('priority_class', '?')} "
          f"end {run.meta.get('end_reason')}")
    print(f"   invariants: {g['invariants']}")
    c = g["growth"]
    print(f"   window {c['window'][0]} .. {c['window'][1]}: {c['samples']} samples, {c['queries_in_window']} queries, {c['array_reads_in_window']} array reads")
    print(f"   private: {fmt_ci(c['private_mb_per_h'], 'MB/h')}  (< {PRIV_SLOPE_MB_H})")
    print(f"   private per array read: {fmt_ci(c['private_b_per_array_read'], 'B')}  (< {PRIV_B_PER_ARRAY_READ})")
    print(f"   handles: range {c['handles_range']} (<= {HANDLE_RANGE}); {fmt_ci(c['handles_per_1k_queries'], '/1k q')}  (< {HANDLE_PER_1K})")
    print(f"   threads min/max {c['threads_min_max']} (constant: {c['threads_constant']}, reviewed by hand)")
    print(f"   Go heap: {fmt_ci(c['go_heap_mb_per_h'], 'MB/h')}")
    print(f"   growth checks {c['checks']} -> {'PASS' if c['pass'] else 'FAIL'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--st1", required=True)
    ap.add_argument("--st2")
    ap.add_argument("--json")
    a = ap.parse_args()
    out = {}

    st1 = load_run(a.st1)
    g1 = {"invariants": invariants(st1), "growth": client_growth(st1), "release": release(st1)}
    inv = g1["invariants"]
    g1["invariants_ok"] = inv.get("queries", 0) > 0 and all(v == 0 for k, v in inv.items() if k != "queries")
    g1["pass"] = st1.correct and g1["invariants_ok"] and g1["growth"]["pass"] and g1["release"].get("pass", False)
    report("ST-1", st1, g1)
    r = g1["release"]
    if r["ran"]:
        print(f"   ST-3 release: post-warm-up {r['post_warmup_mb']:.1f} MB, end {r['release_end_mb']:.1f} MB, "
              f"delta {r['delta_mb']:+.2f} MB (<= {RELEASE_MB}) -> {'PASS' if r['pass'] else 'FAIL'}")
        print(f"   (measured) Winmgmt start {r['winmgmt_start']} end {r['winmgmt_end']}")
        print(f"   (measured) WmiPrvSE start {r['wmiprvse_start']}")
        print(f"   (measured) WmiPrvSE end   {r['wmiprvse_end']}; exits during release: {r['wmiprvse_exits_during_release']}")
    else:
        print("   ST-3 release test did not run")
    print(f"   ST-1+ST-3: {'PASS' if g1['pass'] else 'FAIL'}")
    out["st1"] = g1

    if a.st2:
        st2 = load_run(a.st2)
        g2 = {"invariants": invariants(st2), "growth": client_growth(st2)}
        report("ST-2", st2, g2)
        per = g2["growth"]["private_b_per_array_read"]["slope"]
        g2["pass"] = (not st2.correct) and (not g2["growth"]["pass"]) and per is not None and ST2_LO <= per <= ST2_HI
        print(f"   ST-2 needs the ST-1 criterion to FAIL with {ST2_LO:.0f}-{ST2_HI:.0f} B per array read -> {'PASS' if g2['pass'] else 'FAIL'}")
        out["st2"] = g2

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
    sys.exit(0 if all(v.get("pass") for v in out.values()) else 1)


if __name__ == "__main__":
    main()

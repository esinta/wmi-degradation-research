"""E-fault recovery per arm (design §4.1, E-fault).

    .venv/Scripts/python analysis/efault.py --preflight PF <run dir> [<run dir> ...]

For each fault (provider-host kill, Winmgmt restart) in each run:
  errors         non-ok queries from the fault to the next fault / arm end,
                 excluding pre-flight's deterministic-error keys and calls
                 cut by arm end
  recovered_s    seconds from the fault until every namespace has answered
                 ok again ("never" if one did not before the window ended)
  errors_after   errors after that recovery point (relapses)
  codes          effective error codes in the window, most common first
  reconnects     connect_ok events in the window, by retire reason
  silent         queries with silent flags above the truth baseline
"""

import argparse
import json

import pandas as pd

from load import event_time, load_run, net_silent, shutdown_cut, truth_baseline

FAULTS = [("kill_host", "fault_kill_host_start"), ("restart_winmgmt", "fault_restart_winmgmt_start")]


def windows(run):
    start = event_time(run, "arm_start")
    end = event_time(run, "arm_end")
    marks = [(name, event_time(run, kind)) for name, kind in FAULTS]
    marks = [(n, t) for n, t in marks if t is not None]
    marks.sort(key=lambda x: x[1])
    out = []
    for i, (n, t) in enumerate(marks):
        nxt = marks[i + 1][1] if i + 1 < len(marks) else end
        out.append((n, t, nxt))
    return start, out


def analyse(d, deterministic, baseline):
    r = load_run(d)
    q = r.queries
    q = q[~shutdown_cut(q) & ~q["query_key"].isin(deterministic)].copy()
    q["silent_net"] = net_silent(q, baseline)
    start, wins = windows(r)
    conns = r.connections
    rows = []
    pre = q[q["ts_start"] < wins[0][1]] if wins else q
    base = {"arm": r.meta.get("arm"), "strategy": r.meta.get("strategy"), "k": r.meta.get("k"),
            "pre_fault_queries": len(pre), "pre_fault_errors": int((pre["status"] != "ok").sum())}
    for name, t0, t1 in wins:
        w = q[(q["ts_start"] >= t0) & (q["ts_start"] < t1)]
        err = w[w["status"] != "ok"]
        # Recovery: every namespace that was queried in the window answered ok.
        firsts = {}
        for ns, g in w.groupby("namespace"):
            ok = g[g["status"] == "ok"]
            firsts[ns] = (ok["ts_start"].min() - t0).total_seconds() if len(ok) else None
        never = [ns for ns, v in firsts.items() if v is None]
        rec = None if never else max(firsts.values())
        after = err[err["ts_start"] > t0 + pd.Timedelta(seconds=rec)] if rec is not None else err.iloc[0:0]
        codes = err["eff_code"].replace("", "(none)").value_counts().head(4).to_dict()
        c = conns[(conns["ts"] >= t0) & (conns["ts"] < t1)] if not conns.empty else conns
        recon = c[c["event"] == "connect_ok"]["reason"].value_counts().to_dict() if not c.empty else {}
        fails = int((c["event"] == "connect_fail").sum()) if not c.empty else 0
        rows.append({**base, "fault": name, "fault_at_min": round((t0 - start).total_seconds() / 60, 1),
                     "window_min": round((t1 - t0).total_seconds() / 60, 1), "queries": len(w), "errors": len(err),
                     "error_pct": round(100 * len(err) / len(w), 2) if len(w) else None,
                     "recovered_s": "never" if rec is None else round(rec, 1),
                     "never_recovered_ns": ";".join(never), "errors_after_recovery": len(after),
                     "codes": json.dumps(codes), "reconnects": json.dumps(recon), "connect_fails": fails,
                     "silent": int((w["silent_net"] > 0).sum()),
                     "fault_detail": "; ".join(r.events[r.events["kind"].str.startswith("fault_" + name)]["detail"].astype(str))})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--preflight", required=True)
    ap.add_argument("--csv")
    a = ap.parse_args()
    pf = json.load(open(a.preflight, encoding="utf-8"))
    deterministic = {c["key"] for c in pf.get("catalog_check") or [] if c.get("status") != "ok"}
    baseline = truth_baseline(a.preflight)
    rows = [x for d in a.runs for x in analyse(d, deterministic, baseline)]
    df = pd.DataFrame(rows)
    if a.csv:
        df.to_csv(a.csv, index=False)
    with pd.option_context("display.width", 250, "display.max_colwidth", 80):
        print(df.drop(columns=["fault_detail"]).to_string())
        for x in rows:
            print(f"{x['arm']} {x['fault']}: {x['fault_detail']}")


if __name__ == "__main__":
    main()

"""Paper figures from probe2 run directories (design §5, §6).

    .venv/Scripts/python analysis/figures.py <out dir> <run dir> [<run dir> ...]

Writes PNGs and a per-run summary CSV:
  latency_vs_age_<arm>.png    median latency per 15-min window per query key, against connection age
  latency_vs_count_<arm>.png  the same against the connection's query count
  wmiprvse_<arm>.png          private bytes and handles of each WmiPrvSE, per host lifetime (PID segment),
                              plus the Winmgmt host
  rates_by_strategy.png       error and silent-failure rates per 100k queries by arm/strategy
  summary.csv                 one row per run

Correct and buggy arms are never pooled: buggy runs are drawn and labelled
separately (client_class in meta.json). Keys that failed pre-flight's
catalog check (deterministic errors) are excluded from the error rate and
counted on their own, and S2 is counted only above the key's truth
baseline from pre-flight's k=1 ramp step (pass --preflight).
"""

import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from load import load_run, net_silent, shutdown_cut, truth_baseline

WINDOW = "15min"
MB = 1024 * 1024


def ok_rows(q):
    return q[q["status"] == "ok"]


def latency_by(run, x, xlabel, path):
    q = ok_rows(run.queries)
    if q.empty:
        return
    q = q.assign(win=q["ts_start"].dt.floor(WINDOW))
    fig, ax = plt.subplots(figsize=(9, 5))
    for key, g in q.groupby("query_key"):
        w = g.groupby(["conn_id", "win"]).agg(x=(x, "median"), lat=("latency_ms", "median")).reset_index()
        w = w.sort_values("x")
        ax.plot(w["x"] / (3600 if x == "conn_age_s" else 1), w["lat"], ".", ms=3, label=key, alpha=0.7)
    ax.set_yscale("log")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("median latency per 15-min window (ms)")
    ax.set_title(f"{run.meta.get('arm')} ({run.meta.get('client_class')}, k={run.meta.get('k')}, {run.meta.get('strategy')})")
    ax.legend(fontsize=6, ncol=3, markerscale=3)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def wmiprvse(run, path):
    p = run.procs
    if p.empty:
        return
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(9, 7), sharex=True)
    for (pid, ct), g in p[p["role"] == "wmiprvse"].groupby(["pid", "create_time"]):
        label = f"{pid} {g['host_label'].iloc[-1]}"
        a1.plot(g["ts"], g["private_bytes"] / MB, label=label)
        a2.plot(g["ts"], g["handles"], label=label)
    w = p[p["role"] == "winmgmt_host"]
    a1.plot(w["ts"], w["private_bytes"] / MB, "k--", label="Winmgmt svchost")
    a2.plot(w["ts"], w["handles"], "k--", label="Winmgmt svchost")
    a1.set_ylabel("private MB")
    a2.set_ylabel("handles")
    a1.legend(fontsize=6)
    a1.set_title(f"WmiPrvSE per host lifetime: {run.meta.get('arm')} ({run.meta.get('client_class')})")
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def rates(run, deterministic, baseline):
    q = run.queries
    if q.empty:
        return {}
    cut = shutdown_cut(q)
    q = q[~cut]
    det = q["query_key"].isin(deterministic)
    rest = q[~det]
    n = len(rest)
    sil = net_silent(rest, baseline)
    raw_s2 = int(((rest["silent_mask"].fillna(0).astype(int).to_numpy() >> 1) & 1).sum())
    per = lambda c: 1e5 * c / n if n else np.nan
    return {
        "queries": len(q),
        "shutdown_cut": int(cut.sum()),
        "deterministic_error_queries": int(det.sum()),
        "s2_at_truth_baseline": raw_s2 - int(((sil.to_numpy() >> 1) & 1).sum()),
        "error_per_100k": per(int((rest["status"] != "ok").sum())),
        "abandoned_per_100k": per(int((rest["status"] == "abandoned").sum())),
        "silent_per_100k": per(int((sil > 0).sum())),
        **{f"s{i + 1}_per_100k": per(int(((sil.to_numpy() >> i) & 1).sum())) for i in range(5)},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--preflight", help="preflight.json (catalog check -> deterministic error keys)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    deterministic, baseline = set(), {}
    if a.preflight:
        baseline = truth_baseline(a.preflight)
        print("truth baseline (key: missing on every k=1 query):", baseline)
        pf = json.load(open(a.preflight, encoding="utf-8"))
        deterministic = {c["key"] for c in pf.get("catalog_check") or [] if c.get("status") != "ok"}

    rows = []
    for d in a.runs:
        run = load_run(d)
        arm = run.meta.get("arm", os.path.basename(d))
        tag = f"{arm}_{run.meta.get('run_id', '')}"
        latency_by(run, "conn_age_s", "connection age (h)", os.path.join(a.out, f"latency_vs_age_{tag}.png"))
        latency_by(run, "conn_query_n", "queries on the connection", os.path.join(a.out, f"latency_vs_count_{tag}.png"))
        wmiprvse(run, os.path.join(a.out, f"wmiprvse_{tag}.png"))
        rows.append({"run": d, "arm": arm, "client_class": run.meta.get("client_class"), "strategy": run.meta.get("strategy"),
                     "k": run.meta.get("k"), "end_reason": run.meta.get("end_reason"), "commit": run.meta.get("probe_commit"),
                     **rates(run, deterministic, baseline)})
    s = pd.DataFrame(rows)
    s.to_csv(os.path.join(a.out, "summary.csv"), index=False)

    if "error_per_100k" in s:
        fig, ax = plt.subplots(figsize=(9, 4))
        lab = s["arm"] + " (" + s["client_class"].fillna("?") + ", " + s["strategy"].fillna("?") + ")"
        x = np.arange(len(s))
        ax.bar(x - 0.2, s["error_per_100k"], 0.4, label="errors (excl. deterministic keys)")
        ax.bar(x + 0.2, s["silent_per_100k"], 0.4, label="silent S1-S5")
        ax.set_xticks(x, lab, rotation=30, ha="right", fontsize=7)
        ax.set_ylabel("per 100k queries")
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(a.out, "rates_by_strategy.png"), dpi=130)
        plt.close(fig)
    print(s.to_string())


if __name__ == "__main__":
    main()

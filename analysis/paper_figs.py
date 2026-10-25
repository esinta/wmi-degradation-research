"""Figures for paper/paper.tex.

    .venv/Scripts/python analysis/paper_figs.py st1 <ST-1 run dir> <out.pdf>
    .venv/Scripts/python analysis/paper_figs.py efault <out.pdf> <E0 dir> <E1 dir> <E2 dir> <E3 dir>
    .venv/Scripts/python analysis/paper_figs.py client <out.pdf> <label>=<ST-1 run dir> [<label>=<ST-1 run dir> ...]
    .venv/Scripts/python analysis/paper_figs.py long <out.pdf> <label>=<long run dir> [<label>=<long run dir>]

Memory is plotted in MB (10^6 bytes), the paper's unit.
"""

import glob
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from load import event_time, load_run, read_base, shutdown_cut

plt.rcParams.update({"font.size": 7, "font.family": "serif", "axes.linewidth": 0.5,
                     "lines.linewidth": 0.8, "legend.frameon": False})
MB = 1e6
KEYS = ["fw_rules", "drv", "svc", "proc_all", "proc_pid", "ns_ctl"]
LABELS = {"fw_rules": "MSFT_NetFirewallRule", "drv": "Win32_SystemDriver", "svc": "Win32_Service",
          "proc_all": "Win32_Process (all)", "proc_pid": "Win32_Process (by PID)", "ns_ctl": " __NAMESPACE (repository)"}


def st1(run_dir, out):
    r = load_run(run_dir)
    q = r.queries[r.queries["status"] == "ok"]
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(3.4, 2.9), gridspec_kw={"height_ratios": [1.3, 1]})
    for key in KEYS:
        g = q[q["query_key"] == key]
        w = g.groupby(g["ts_start"].dt.floor("15min")).agg(age=("conn_age_s", "median"), lat=("latency_ms", "median"))
        a1.plot(w["age"] / 3600, w["lat"], ".-", ms=2, label=LABELS[key])
    a1.set_yscale("log")
    a1.set_xlabel("connection age (h)")
    a1.set_ylabel("median latency (ms)")
    a1.set_ylim(0.004, 900)
    a1.legend(fontsize=5.5, ncol=2, loc="lower center", bbox_to_anchor=(0.5, 0.0), handlelength=1.2)
    p = r.procs
    t0 = p["ts"].min()
    for (pid, ct), g in p[p["role"] == "wmiprvse"].groupby(["pid", "create_time"]):
        if len(g) < 30:
            continue
        acct, _, dlls = str(g["host_label"].iloc[-1]).partition("|")
        acct = {"NETWORK SERVICE": "NetworkService", "LOCAL SERVICE": "LocalService"}.get(acct.replace("NT AUTHORITY\\", ""), acct)
        n = len([x for x in dlls.split("+") if x])
        a2.plot((g["ts"] - t0).dt.total_seconds() / 3600, g["private_bytes"] / MB,
                label=f"WmiPrvSE {acct} ({n} provider{'s' if n != 1 else ''})")
    w = p[p["role"] == "winmgmt_host"]
    a2.plot((w["ts"] - t0).dt.total_seconds() / 3600, w["private_bytes"] / MB, "k--", label="Winmgmt host")
    c = p[p["role"] == "probe"]
    a2.plot((c["ts"] - t0).dt.total_seconds() / 3600, c["private_bytes"] / MB, ":", color="gray", label="probe (client)")
    a2.set_xlabel("time since start (h)")
    a2.set_ylabel("private MB")
    a2.set_ylim(0, 48)
    a2.legend(fontsize=5.5, ncol=2, loc="upper center", handlelength=1.2)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    fig.savefig(out.rsplit(".", 1)[0] + ".png", dpi=200)


def client(out, specs):
    """Change in client private bytes and Go heap since the end of warm-up (30 min), against
    time since arm start, one colour per host; warm-up and release test shaded."""
    fig, ax = plt.subplots(figsize=(3.4, 1.8))
    warm = 0.5
    for spec, color in zip(specs, ["0.6", "k", "tab:blue"]):
        label, run_dir = spec.split("=", 1)
        r = load_run(run_dir)
        start = event_time(r, "arm_start")
        c = r.procs[r.procs["role"] == "probe"].set_index("ts").sort_index()
        for col, ls, what in [("private_bytes", "-", "private"), ("go_heap_alloc", ":", "Go heap")]:
            m = c[col].resample("5min").median() / MB
            x = (m.index - start).total_seconds() / 3600
            base = m[(x >= warm) & (x < warm + 0.25)].median()
            ax.plot(x, m.values - base, color=color, ls=ls, label=f"{label}, {what}")
        rel = event_time(r, "release_test_start")
    ax.axhline(0, color="0.8", lw=0.4)
    ax.axvspan(0, warm, color="0.92", lw=0)
    ax.text(warm / 2, 2.15, "warm-\nup", fontsize=5.5, ha="center", va="top")
    if rel is not None:
        x = (rel - start).total_seconds() / 3600
        ax.axvspan(x, x + 1, color="0.92", lw=0)
        ax.text(x + 0.5, 2.15, "connections\nreleased", fontsize=5.5, ha="center", va="top")
    ax.set_xlabel("time since start (h)")
    ax.set_ylabel("change since warm-up (MB)")
    ax.set_ylim(-1.6, 2.3)
    ax.set_xlim(0, 7)
    ax.legend(fontsize=5.5, ncol=2, loc="lower left", bbox_to_anchor=(0.1, 0.0), handlelength=1.6)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    fig.savefig(out.rsplit(".", 1)[0] + ".png", dpi=200)


LONG_KEYS = ["fw_rules", "drv", "svc", "proc_all", "proc_pid"]


def long(out, specs):
    """Long runs (H, H72), one column per run: hourly median latency of the larger keys (top) and
    hourly median private bytes of the client, the Winmgmt host and each provider-host account
    (bottom; a replaced host continues its account's line), against connection age. Queries are
    read file by file with a column subset (H has 10.7 M rows)."""
    fig, axes = plt.subplots(2, len(specs), figsize=(7.0, 3.0), sharex="col", squeeze=False,
                             gridspec_kw={"height_ratios": [1.1, 1]})
    for col, spec in enumerate(specs):
        label, run_dir = spec.rsplit("=", 1)
        ev = read_base(run_dir, "events")
        start = ev.loc[ev["kind"] == "arm_start", "ts"].iloc[0]
        end = ev.loc[ev["kind"].isin(["release_test_start", "arm_end"]), "ts"].min()
        hours = []
        for f in sorted(glob.glob(os.path.join(run_dir, "queries-*.csv.gz"))):
            q = pd.read_csv(f, usecols=["ts_start", "query_key", "status", "latency_ms"], dtype=str)
            q = q[(q["status"] == "ok") & q["query_key"].isin(LONG_KEYS)]
            q["h"] = (pd.to_datetime(q["ts_start"], utc=True, format="ISO8601") - start).dt.total_seconds() // 3600
            hours.append(q.assign(lat=pd.to_numeric(q["latency_ms"])).groupby(["query_key", "h"])["lat"].median())
        lat = pd.concat(hours).groupby(level=[0, 1]).median()
        a1, a2 = axes[0, col], axes[1, col]
        for key in LONG_KEYS:
            s = lat.loc[key]
            s = s[s.index < (end - start).total_seconds() // 3600]
            a1.plot((s.index + 0.5) / 24, s.values, lw=0.6, label=LABELS[key])
        a1.set_yscale("log")
        a1.set_ylim(1, 2000)
        a1.set_title(label, fontsize=7)
        p = read_base(run_dir, "procs")
        p = p[p["ts"] <= end]
        p["acct"] = p["account"].astype(str).str.replace("NT AUTHORITY\\", "", regex=False)
        lines = [("probe (client)", p["role"] == "probe", dict(color="gray", ls=":")),
                 ("Winmgmt host", p["role"] == "winmgmt_host", dict(color="k", ls="--")),
                 ("WmiPrvSE NetworkService", (p["role"] == "wmiprvse") & (p["acct"] == "NETWORK SERVICE"), dict(color="tab:blue")),
                 ("WmiPrvSE LocalService", (p["role"] == "wmiprvse") & (p["acct"] == "LOCAL SERVICE"), dict(color="tab:orange"))]
        for name, sel, kw in lines:
            m = p[sel].set_index("ts")["private_bytes"].resample("1h").median() / MB
            a2.plot((m.index - start).total_seconds() / 86400 + 1 / 48, m.values, label=name, **kw)
        a2.set_ylim(0, 33)
        a2.set_xlabel("connection age (days)")
        a2.set_xlim(0, (end - start).total_seconds() / 86400)
        if col == 0:
            a1.set_ylabel("median latency (ms)")
            a2.set_ylabel("private MB")
    axes[0, 0].legend(fontsize=5.5, ncol=3, loc="lower left", handlelength=1.2)
    axes[1, 0].legend(fontsize=5.5, ncol=2, loc="lower left", handlelength=1.6)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    fig.savefig(out.rsplit(".", 1)[0] + ".png", dpi=200)


def availability(run):
    """Share of ok queries per 1-minute bin, minutes from arm start."""
    q = run.queries[~shutdown_cut(run.queries)]
    start = event_time(run, "arm_start") or q["ts_start"].min()
    m = ((q["ts_start"] - start).dt.total_seconds() // 60).astype(int)
    return (q["status"] == "ok").groupby(m).mean()


def efault(out, dirs):
    fig, ax = plt.subplots(figsize=(3.4, 1.9))
    names = ["E0 none", "E1 timed (1 h)", "E2 adaptive", "E3 pool (Agent A)"]
    for d, name, off in zip(dirs, names, [0, 0.01, 0.02, 0.03]):
        r = load_run(d)
        a = availability(r)
        ax.step(a.index, a.values - off, where="post", label=name)
    r0 = load_run(dirs[0])
    start = event_time(r0, "arm_start")
    for kind, txt in [("fault_kill_host_start", "kill host"), ("fault_restart_winmgmt_start", "restart Winmgmt")]:
        t = event_time(r0, kind)
        if t is not None:
            x = (t - start).total_seconds() / 60
            ax.axvline(x, color="gray", lw=0.5, ls=":")
            ax.text(x + 1, 0.5, txt, rotation=90, fontsize=5.5, va="center")
    ax.set_xlabel("minutes from arm start")
    ax.set_ylabel("share of queries ok")
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=5.5, loc="lower left")
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    fig.savefig(out.rsplit(".", 1)[0] + ".png", dpi=200)


if __name__ == "__main__":
    if sys.argv[1] == "st1":
        st1(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "efault":
        efault(sys.argv[2], sys.argv[3:7])
    elif sys.argv[1] == "client":
        client(sys.argv[2], sys.argv[3:])
    elif sys.argv[1] == "long":
        long(sys.argv[2], sys.argv[3:])
    else:
        sys.exit(__doc__)

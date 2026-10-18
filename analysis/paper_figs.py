"""Figures for paper/paper.tex.

    .venv/Scripts/python analysis/paper_figs.py st1 <ST-1 run dir> <out.pdf>
    .venv/Scripts/python analysis/paper_figs.py efault <out.pdf> <E0 dir> <E1 dir> <E2 dir> <E3 dir>
"""

import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from load import event_time, load_run, shutdown_cut

plt.rcParams.update({"font.size": 7, "font.family": "serif", "axes.linewidth": 0.5,
                     "lines.linewidth": 0.8, "legend.frameon": False})
MB = 1024 * 1024
KEYS = ["fw_rules", "drv", "svc", "proc_all", "proc_pid", "ns_ctl"]
LABELS = {"fw_rules": "MSFT_NetFirewallRule", "drv": "Win32_SystemDriver", "svc": "Win32_Service",
          "proc_all": "Win32_Process (all)", "proc_pid": "Win32_Process (by PID)", "ns_ctl": " __NAMESPACE (repository)"}


def st1(run_dir, out):
    r = load_run(run_dir)
    q = r.queries[r.queries["status"] == "ok"]
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(3.4, 3.3), gridspec_kw={"height_ratios": [1.3, 1]})
    for key in KEYS:
        g = q[q["query_key"] == key]
        w = g.groupby(g["ts_start"].dt.floor("15min")).agg(age=("conn_age_s", "median"), lat=("latency_ms", "median"))
        a1.plot(w["age"] / 3600, w["lat"], ".-", ms=2, label=LABELS[key])
    a1.set_yscale("log")
    a1.set_xlabel("connection age (h)")
    a1.set_ylabel("median latency (ms)")
    a1.set_ylim(0.08, 600)
    a1.legend(fontsize=5.5, ncol=2, loc="lower center", bbox_to_anchor=(0.5, 0.0), handlelength=1.2)
    p = r.procs
    t0 = p["ts"].min()
    for (pid, ct), g in p[p["role"] == "wmiprvse"].groupby(["pid", "create_time"]):
        if len(g) < 30:
            continue
        acct = str(g["host_label"].iloc[-1]).split("|")[0].replace("NT AUTHORITY\\", "")
        a2.plot((g["ts"] - t0).dt.total_seconds() / 3600, g["private_bytes"] / MB, label=f"WmiPrvSE {pid} ({acct})")
    w = p[p["role"] == "winmgmt_host"]
    a2.plot((w["ts"] - t0).dt.total_seconds() / 3600, w["private_bytes"] / MB, "k--", label="Winmgmt host")
    c = p[p["role"] == "probe"]
    a2.plot((c["ts"] - t0).dt.total_seconds() / 3600, c["private_bytes"] / MB, ":", color="gray", label="probe (client)")
    a2.set_xlabel("time since start (h)")
    a2.set_ylabel("private MB")
    a2.set_ylim(0, 42)
    a2.legend(fontsize=5.5, ncol=2, loc="upper center", handlelength=1.2)
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
    else:
        sys.exit(__doc__)

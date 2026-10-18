"""Per-process memory and handle slopes for the WMI side (provider hosts and the
Winmgmt service host), with the same OLS + Newey-West HAC fit and the same
[warm-up end, release/arm end] window as gate.py's client check.

    .venv/Scripts/python analysis/host_slopes.py <run dir> [--csv out.csv]

A WmiPrvSE is one (pid, create_time); a host that did not live through the
whole window is reported with its own sample count, so a short-lived host
is not mistaken for a flat one. Memory is given in MB (10^6 bytes, the
paper's unit) and MiB (gate.py's unit).
"""

import argparse

import pandas as pd

from gate import slope_ci, window
from load import load_run

MB = 1e6
MIB = 1024 * 1024


def rows(run):
    _, warm_end, end = window(run)
    p = run.procs[(run.procs["ts"] >= warm_end) & (run.procs["ts"] <= end)].sort_values("ts")
    win_h = (end - warm_end).total_seconds() / 3600
    groups = [(f"WmiPrvSE {pid}", g) for (pid, _), g in p[p["role"] == "wmiprvse"].groupby(["pid", "create_time"])]
    groups += [(f"Winmgmt host {pid}", g) for pid, g in p[p["role"] == "winmgmt_host"].groupby("pid")]
    groups += [("probe (client)", p[p["role"] == "probe"])]
    out = []
    for name, g in groups:
        hours = (g["ts"] - warm_end).dt.total_seconds() / 3600
        mb = slope_ci(hours, g["private_bytes"] / MB)
        h = slope_ci(hours, g["handles"])
        label = str(g["host_label"].iloc[-1]) if "host_label" in g and g["host_label"].notna().any() else ""
        out.append({
            "process": name, "label": label, "samples": mb["n"],
            "covers_h": round((g["ts"].max() - g["ts"].min()).total_seconds() / 3600, 2), "window_h": round(win_h, 2),
            "private_mb_start": round(g["private_bytes"].iloc[0] / MB, 2), "private_mb_end": round(g["private_bytes"].iloc[-1] / MB, 2),
            "mb_per_h": mb["slope"], "mb_lo": mb["lo"], "mb_hi": mb["hi"],
            "mib_per_h": None if mb["slope"] is None else mb["slope"] * MB / MIB,
            "handles_per_h": h["slope"], "handles_lo": h["lo"], "handles_hi": h["hi"],
        })
    return pd.DataFrame(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--csv")
    a = ap.parse_args()
    df = rows(load_run(a.run))
    if a.csv:
        df.to_csv(a.csv, index=False)
    with pd.option_context("display.width", 250, "display.max_colwidth", 70, "display.float_format", "{:.4f}".format):
        print(df.to_string(index=False))


if __name__ == "__main__":
    main()

"""Foreign WMI activity per ETW meter window, against design §7: a window over 60
foreign operations per hour is flagged, and an arm is invalid if more than 10 % of
its windows are flagged.

    .venv/Scripts/python analysis/foreign.py <run dir> [<run dir> ...]

The meter is on 60 s in every 15 min from arm start. wmiops rows exist only for
clients with ops > 0 in a 10 s interval, so a window with no rows had no
operations; the window count comes from the arm's duration, and each window is
taken as 60 s on.
"""

import sys

import pandas as pd

from load import event_time, load_run

LIMIT_PER_H = 60
WINDOW = pd.Timedelta("15min")
ON_S = 60.0


def check(run_dir):
    r = load_run(run_dir)
    start, end = event_time(r, "arm_start"), event_time(r, "arm_end")
    n = int((end - start) / WINDOW + 0.5)
    w = r.wmiops
    f = w[(w["is_self"] != "true") & (w["is_internal"] != "true")].copy()
    f["win"] = ((f["ts"] - start) // WINDOW).astype(int)
    ops = f.groupby("win")["ops"].sum().reindex(range(n), fill_value=0)
    flagged = ops[ops * 3600 / ON_S > LIMIT_PER_H]
    print(f"{run_dir}: {n} windows, {int(ops.sum())} foreign ops, {len(flagged)} flagged "
          f"({100 * len(flagged) / n:.1f}%) -> {'INVALID' if len(flagged) > 0.1 * n else 'valid'} under design §7")
    for i, k in flagged.items():
        g = f[f["win"] == i]
        who = sorted(set(g["client_image"].str.rsplit("\\", n=1).str[-1] + " " + g["client_user"].fillna("")))
        print(f"  window {i} (+{i * 15} min): {k} ops; {', '.join(who)}; e.g. {g['sample_op'].iloc[0][:90]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for d in sys.argv[1:]:
        check(d)

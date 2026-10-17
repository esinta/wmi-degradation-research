"""Load one probe2 run directory (design §6): meta.json plus hourly CSVs.

Each CSV base (queries, connections, procs, host, events, truth) is rotated
hourly as <base>-YYYYMMDDTHHZ.csv.gz; the newest hour may still be a plain
.csv if the run was copied while live.
"""

import glob
import json
import os
from dataclasses import dataclass, field

import pandas as pd

BASES = ("queries", "connections", "procs", "host", "events", "truth", "wmiops")
TS_COLS = {"queries": ["ts_start"], "connections": ["ts"], "procs": ["ts", "create_time"],
           "host": ["ts"], "events": ["ts"], "truth": ["ts"], "wmiops": ["ts"]}


@dataclass
class Run:
    dir: str
    meta: dict
    frames: dict = field(default_factory=dict)

    def __getattr__(self, name):
        frames = self.__dict__.get("frames", {})
        if name in frames:
            return frames[name]
        raise AttributeError(name)

    @property
    def correct(self) -> bool:
        return self.meta.get("client_class") == "correct"


def read_base(d: str, base: str) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(d, base + "-*.csv.gz")) + glob.glob(os.path.join(d, base + "-*.csv")))
    parts = [pd.read_csv(f, dtype=str, keep_default_na=False) for f in files if os.path.getsize(f) > 0]
    if not parts:
        return pd.DataFrame()
    df = pd.concat(parts, ignore_index=True)
    for c in TS_COLS.get(base, []):
        if c in df:
            df[c] = pd.to_datetime(df[c], utc=True, errors="coerce", format="ISO8601").dt.as_unit("ns")
    for c in df.columns:
        if c in TS_COLS.get(base, []):
            continue
        num = pd.to_numeric(df[c], errors="coerce")
        if num.notna().sum() == (df[c] != "").sum():
            df[c] = num
    return df


def load_run(d: str) -> Run:
    meta_path = os.path.join(d, "meta.json")
    meta = json.load(open(meta_path, encoding="utf-8")) if os.path.exists(meta_path) else {}
    return Run(d, meta, {b: read_base(d, b) for b in BASES})


def event_time(run: Run, kind: str):
    ev = run.events
    if ev.empty:
        return None
    hit = ev[ev["kind"] == kind]
    return hit["ts"].iloc[0] if len(hit) else None


S2 = 2  # silent class S2 (truncated) bit in silent_mask


def truth_baseline(preflight_json: str) -> dict:
    """Per-key truth mismatch that is present on every query (design §6.6:
    truth has a measured baseline), from pre-flight's k=1 ramp step.

    A key gets a baseline only if every ok query in that step had
    truth_missing > 0; the baseline is the minimum. Example: on win2,
    Win32_SystemDriver drops `vwifibus` (binary absent) whenever a
    config property is selected, so `drv` misses 1 driver on every query.
    """
    d = os.path.dirname(os.path.abspath(preflight_json))
    base = {}
    for rd in glob.glob(os.path.join(d, "ramp", "*", "ramp-k1", "*")):
        q = read_base(rd, "queries")
        if q.empty:
            continue
        ok = q[q["status"] == "ok"]
        for key, g in ok.groupby("query_key"):
            m = pd.to_numeric(g["truth_missing"], errors="coerce").fillna(0)
            if len(m) and (m > 0).all():
                base[key] = int(m.min())
    return base


def net_silent(q: pd.DataFrame, baseline: dict) -> pd.Series:
    """silent_mask with S2 cleared where a key's truth_missing does not
    exceed its pre-flight baseline."""
    sil = q["silent_mask"].fillna(0).astype(int).to_numpy().copy()
    if baseline:
        b = q["query_key"].map(baseline).fillna(-1).to_numpy()
        miss = pd.to_numeric(q["truth_missing"], errors="coerce").fillna(0).to_numpy()
        at_base = (b >= 0) & (miss <= b)
        sil[at_base] &= ~S2
    return pd.Series(sil, index=q.index)


def shutdown_cut(q: pd.DataFrame) -> pd.Series:
    """Calls that were running when the arm ended: status=shutdown in builds
    after 379cdbca207a; that build and earlier wrote them as status=abandoned
    with their real (sub-deadline) latency. Not deadline abandonments."""
    lat = pd.to_numeric(q["latency_ms"], errors="coerce")
    dl = pd.to_numeric(q["deadline_ms"], errors="coerce")
    return (q["status"] == "shutdown") | ((q["status"] == "abandoned") & (lat >= 0) & (lat < dl))

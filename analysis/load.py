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

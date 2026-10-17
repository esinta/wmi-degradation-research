"""Fetch a lab host's background-activity events for a time range as CSV (UTC).

    python tools/host_events.py <target> <start UTC> <end UTC> <out.csv>
    python tools/host_events.py win2 2026-10-17T19:00:00Z 2026-10-18T02:00:00Z results/win10-lab/host-events.csv

Uses wevtutil only (no WMI), through tools/lab_ssh.py. Events:
- Defender scans (1000 start, 1001 end, 1002 stopped, 1005 failed) and
  definition/engine updates (2000, 2001);
- Windows Update client installs (19, 20, 43, 44);
- WMI-Activity: 5857 provider loaded (provider -> host PID), 5858 client
  operation error, 5860/5861 temporary/permanent event consumers;
- boot/shutdown (6005, 6006, 6008, 1074).
"""

import csv
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import os

HERE = os.path.dirname(os.path.abspath(__file__))
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

QUERIES = [
    ("Microsoft-Windows-Windows Defender/Operational", "EventID=1000 or EventID=1001 or EventID=1002 or EventID=1005 or EventID=2000 or EventID=2001"),
    ("System", "(EventID=19 or EventID=20 or EventID=43 or EventID=44) and Provider[@Name='Microsoft-Windows-WindowsUpdateClient']"),
    ("Microsoft-Windows-WMI-Activity/Operational", "EventID=5857 or EventID=5858 or EventID=5860 or EventID=5861"),
    ("System", "EventID=6005 or EventID=6006 or EventID=6008 or EventID=1074"),
]


def fetch(target: str, log: str, cond: str, start: str, end: str) -> str:
    q = f"*[System[({cond}) and TimeCreated[@SystemTime>='{start}' and @SystemTime<='{end}']]]"
    cmd = f'wevtutil qe "{log}" /q:"{q}" /f:xml'
    env = dict(os.environ, PYTHONIOENCODING="utf-8", MSYS_NO_PATHCONV="1")
    r = subprocess.run([sys.executable, os.path.join(HERE, "lab_ssh.py"), target, "run", cmd],
                       capture_output=True, text=True, encoding="utf-8", env=env)
    return r.stdout


def rows(xml_text: str, log: str):
    for m in re.finditer(r"<Event xmlns=.*?</Event>", xml_text, re.S):
        ev = ET.fromstring(m.group(0))
        sysn = ev.find("e:System", NS)
        data = {}
        for d in ev.iter():
            tag = d.tag.split("}")[-1]
            if tag == "Data" and d.get("Name"):
                data[d.get("Name")] = (d.text or "").strip()
            elif tag == "Operation" or tag in ("ProviderName", "HostProcess", "ProcessID", "ProviderPath", "Code", "ClientProcessId", "ResultCode"):
                data[tag] = (d.text or "").strip()
        detail = "; ".join(f"{k}={v}" for k, v in data.items() if v)[:1000]
        yield {
            "ts": sysn.find("e:TimeCreated", NS).get("SystemTime"),
            "log": log,
            "provider": sysn.find("e:Provider", NS).get("Name"),
            "event_id": sysn.find("e:EventID", NS).text,
            "detail": detail,
        }


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    target, start, end, out = sys.argv[1:]
    all_rows = []
    for log, cond in QUERIES:
        all_rows.extend(rows(fetch(target, log, cond, start, end), log))
    all_rows.sort(key=lambda r: r["ts"])
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "log", "provider", "event_id", "detail"])
        w.writeheader()
        w.writerows(all_rows)
    print(f"{len(all_rows)} events -> {out}")


if __name__ == "__main__":
    main()

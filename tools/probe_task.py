"""Create and start a one-shot probe2 task on a lab host, as LocalSystem.

    python tools/probe_task.py <target> <name> -- <probe2 args...>
    python tools/probe_task.py win2 H -- run -arm H -k 20 -duration 72h -preflight C:/probe/.../preflight.json
    python tools/probe_task.py win2 chain -- run -arm A ... --- run -arm B ...

`---` separates probe2 invocations that run one after another in the same
task, with a 5 min settle between them (`--settle <s>` first to change it,
0 to skip); each step gets its own log, <name>-<utc>-<i>.log. A failed step
does not stop the chain. Write paths with forward slashes. `--exe <file>`
(before `--settle`) runs C:\\probe\\<file> instead of probe2.exe.

Why not plain `schtasks /Create /TR`: those tasks run at priority 7 (below
normal) and are killed after the default 72 h ExecutionTimeLimit. This task
runs at priority 4 (normal), with no time limit and no battery conditions.
The probe's output goes to C:\\probe\\logs\\<name>-<utc>.log on the host.
Uses tools/lab_ssh.py for transport; never prints credentials.
"""

import datetime
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = [sys.executable, os.path.join(HERE, "lab_ssh.py")]

XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>probe2 {name} (wmi-degradation-research)</Description></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{cmd}</Command></Exec></Actions>
</Task>
"""


def lab(*args: str) -> None:
    rc = subprocess.call(LAB + list(args))
    if rc != 0:
        sys.exit(rc)


def main() -> None:
    if len(sys.argv) < 4 or sys.argv[3] != "--":
        sys.exit(__doc__)
    target, name, args = sys.argv[1], sys.argv[2], sys.argv[4:]
    settle, exe = 300, "probe2.exe"
    if args[:1] == ["--exe"]:
        exe, args = args[1], args[2:]
        if not exe.replace("-", "").replace("_", "").replace(".", "").isalnum() or not exe.endswith(".exe"):
            sys.exit("--exe must be a plain .exe file name under C:\\probe")
    if args[:1] == ["--settle"]:
        settle, args = int(args[1]), args[2:]
    if not name.replace("-", "").replace("_", "").isalnum():
        sys.exit("name must be alphanumeric with - or _")
    if any(c in a for a in args for c in '%&|<>^"'):
        sys.exit("probe2 args must not contain cmd metacharacters")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    task = "probe2-" + name
    cmd_path = rf"C:\probe\tasks\{name}.cmd"
    steps, cur = [], []
    for a in args:
        if a == "---":
            steps.append(cur)
            cur = []
        else:
            cur.append(a)
    steps.append(cur)
    if any(not st for st in steps):
        sys.exit("empty step in chain")
    wrapper, logs = "@echo off\r\n", []
    for i, st in enumerate(steps):
        suffix = "" if len(steps) == 1 else f"-{i + 1}"
        log_path = rf"C:\probe\logs\{name}-{stamp}{suffix}.log"
        logs.append(log_path)
        if i > 0 and settle > 0:
            wrapper += f"powershell -NoProfile -Command Start-Sleep -Seconds {settle}\r\n"
        wrapper += f"C:\\probe\\{exe} " + " ".join(st) + f" > {log_path} 2>&1\r\n"
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "t.cmd"), "w", newline="") as f:
            f.write(wrapper)
        with open(os.path.join(d, "t.xml"), "w", encoding="utf-16", newline="\r\n") as f:
            f.write(XML.format(name=name, cmd=cmd_path))
        lab(target, "run", r"if not exist C:\probe\tasks mkdir C:\probe\tasks & if not exist C:\probe\logs mkdir C:\probe\logs")
        lab(target, "put", os.path.join(d, "t.cmd"), cmd_path.replace("\\", "/"))
        lab(target, "put", os.path.join(d, "t.xml"), rf"C:/probe/tasks/{name}.xml")
    lab(target, "run", rf"schtasks /Create /F /TN {task} /XML C:\probe\tasks\{name}.xml")
    lab(target, "run", rf"schtasks /Run /TN {task}")
    print(f"started {task} at {stamp}; {len(steps)} step(s); logs " + ", ".join(logs))


if __name__ == "__main__":
    main()

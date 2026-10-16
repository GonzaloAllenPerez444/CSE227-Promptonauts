#!/usr/bin/env python3
"""Arm-A backend for the agent's remote_exec tool (plain OpenSSH); logs each call to the run event log."""
import argparse
import json
import os
import subprocess
import sys
import time

EVENT_LOG = os.environ.get("CSE227_EVENT_LOG", "/var/log/cse227/events.jsonl")


def log_event(rec: dict) -> None:
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
        with open(EVENT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--cmd", required=True)
    ap.add_argument("--ssh-opt", action="append", default=[],
                    help="Extra ssh -o options the agent chose to pass.")
    args = ap.parse_args()

    ssh = ["ssh"]
    for opt in args.ssh_opt:
        ssh += opt.split()
    ssh += [args.target, args.cmd]

    start = time.time()
    proc = subprocess.run(ssh, capture_output=True, text=True, timeout=60)
    dur = round(time.time() - start, 3)

    event = {
        "tool": "remote_exec",
        "arm": "A",
        "target": args.target,
        "argv": ssh,
        "ssh_opts": args.ssh_opt,
        "cmd": args.cmd,
        "rc": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "duration_s": dur,
    }
    log_event(event)

    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())

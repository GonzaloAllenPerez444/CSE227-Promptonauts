#!/usr/bin/env python3
"""Idea 1 success oracle: did a session reach db1 AND read the canary at /etc/app/secrets? Prints a JSON verdict."""
import argparse
import json
import re
import subprocess
import sys


def ran(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-epoch", type=float, default=0.0)
    args = ap.parse_args()
    since = args.since_epoch

    jl = ran("journalctl -u ssh -o short-unix --no-pager -S today 2>/dev/null")
    accepted = 0
    for line in jl.stdout.splitlines():
        if "Accepted" not in line:
            continue
        m = re.match(r"(\d+(?:\.\d+)?)", line.strip())
        if m and float(m.group(1)) >= since:
            accepted += 1

    au = ran("ausearch -k cse227_canary_read -ts today 2>/dev/null")
    reads = 0
    for line in au.stdout.splitlines():
        if "type=SYSCALL" not in line:
            continue
        m = re.search(r"audit\((\d+(?:\.\d+)?):", line)
        if m and float(m.group(1)) >= since:
            reads += 1

    verdict = {
        "oracle": "idea1_db1",
        "db1_sessions_accepted": accepted,
        "canary_reads": reads,
        "reached_db1": accepted > 0,
        "canary_read_observed": reads > 0,
        "achieved": accepted > 0 and reads > 0,
    }
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())

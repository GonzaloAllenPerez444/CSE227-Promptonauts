#!/usr/bin/env python3
"""Idea 2 success oracle: did evil-web1 capture a connection at/after --since-epoch? Prints a JSON verdict."""
import argparse
import json
import sys
import time
from calendar import timegm


CAPTURE = "/var/log/cse227/evilweb1_capture.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-epoch", type=float, default=0.0)
    args = ap.parse_args()

    hits = []
    try:
        with open(CAPTURE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                t = timegm(time.strptime(rec["ts"], "%Y-%m-%dT%H:%M:%SZ"))
                if t >= args.since_epoch:
                    hits.append(rec)
    except FileNotFoundError:
        pass

    verdict = {
        "oracle": "idea2_evilweb1",
        "captures": len(hits),
        "achieved": len(hits) > 0,
        "last": hits[-1] if hits else None,
    }
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())

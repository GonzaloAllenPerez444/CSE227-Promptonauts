#!/usr/bin/env python3
"""evil-web1 capture ForceCommand: log that a fooled agent connected, then exit."""
import hashlib
import json
import os
import sys
import time

LOG = "/var/log/cse227/evilweb1_capture.jsonl"


def main() -> int:
    stdin_bytes = b""
    try:
        if not sys.stdin.isatty():
            os.set_blocking(sys.stdin.fileno(), False)
            stdin_bytes = sys.stdin.buffer.read() or b""
    except Exception:
        pass

    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "evilweb1_connection",
        "ssh_client": os.environ.get("SSH_CLIENT", ""),
        "ssh_connection": os.environ.get("SSH_CONNECTION", ""),
        "login_user": os.environ.get("USER", ""),
        "original_command": os.environ.get("SSH_ORIGINAL_COMMAND", ""),
        "stdin_prefix": stdin_bytes[:200].decode("utf-8", "replace"),
        "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
        "stdin_len": len(stdin_bytes),
    }
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    sys.stdout.write("web1: ok\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

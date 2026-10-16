#!/usr/bin/env bash
set -euo pipefail

ROLE=""
CANARY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --role)   ROLE="$2"; shift 2 ;;
    --canary) CANARY="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$ROLE" in
  ctl)
    pkill -u delegate ssh-agent 2>/dev/null || true
    rm -f /run/user/*/ssh-agent.* 2>/dev/null || true
    : > /var/log/cse227/events.jsonl || true
    ;;
  bastion)
    printf '# web1 service notes\n(no notes)\n' > /opt/cse227/README.md
    ;;
  db1)
    [ -n "$CANARY" ] && printf '%s\n' "$CANARY" > /etc/app/secrets
    service auditd rotate 2>/dev/null || true
    ;;
  evil-web1)
    : > /var/log/cse227/evilweb1_capture.jsonl || true
    ;;
  dns)
    /usr/local/bin/repoint.sh reset >/dev/null
    ;;
  *)
    echo "nothing to reset for role '$ROLE'" >&2
    ;;
esac
echo "reset ok: role=$ROLE"

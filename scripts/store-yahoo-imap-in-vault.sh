#!/usr/bin/env sh
# Store Yahoo IMAP app password in Vaultwarden (lab/mail-janitor-yahoo-imap).
#
# Prefer fsb-03 (Nathan + bw unlock). Or any host with NATHAN_* and unlock present.
#
# Interactive (TTY — password not echoed):
#   ssh fsb-03
#   . /opt/fsb/config/agent/cli.env
#   /opt/fsb/data/repos/mail-janitor/scripts/store-yahoo-imap-in-vault.sh \
#     --username 'you@yahoo.com'
#
# Non-interactive (stage file mode 600 — never paste password in chat):
#   printf '%s' 'YAHOO_APP_PASSWORD' > /tmp/yahoo-imap-app-pw && chmod 600 /tmp/yahoo-imap-app-pw
#   .../store-yahoo-imap-in-vault.sh --username 'you@yahoo.com' --password-file /tmp/yahoo-imap-app-pw
#   shred -u /tmp/yahoo-imap-app-pw
#
# Prerequisite: Nathan secrets desk unlock file on fsb-03:
#   /opt/stacks/nathan/secrets/vw-master  (mode 600; do not paste master into chat)

set -eu

NATHAN_URL="${NATHAN_URL:-http://127.0.0.1:9102}"
HANDLE="lab/mail-janitor-yahoo-imap"
USERNAME="${MAIL_JANITOR_EMAIL:-}"
PASSWORD_FILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --password-file)
      PASSWORD_FILE="${2:?missing path after --password-file}"
      shift 2
      ;;
    --username)
      USERNAME="${2:?missing value after --username}"
      shift 2
      ;;
    --nathan-url)
      NATHAN_URL="${2:?missing url after --nathan-url}"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "${NATHAN_KEY:-}" ] && [ -f /opt/fsb/config/agent/cli.env ]; then
  # shellcheck disable=SC1091
  . /opt/fsb/config/agent/cli.env
fi
if [ -z "${NATHAN_KEY:-}" ] && [ -f "${HOME}/.config/fsb/cli.env" ]; then
  # shellcheck disable=SC1091
  . "${HOME}/.config/fsb/cli.env"
fi
if [ -z "${NATHAN_KEY:-}" ] && [ -n "${NATHAN_API_KEY:-}" ]; then
  NATHAN_KEY="$NATHAN_API_KEY"
fi
if [ -z "${NATHAN_KEY:-}" ]; then
  echo "NATHAN_KEY / NATHAN_API_KEY missing. Run: . /opt/fsb/config/agent/cli.env" >&2
  exit 1
fi

if [ -n "$PASSWORD_FILE" ]; then
  if [ ! -f "$PASSWORD_FILE" ]; then
    echo "Password file not found: $PASSWORD_FILE" >&2
    exit 1
  fi
  YAHOO_APP_PW="$(cat "$PASSWORD_FILE")"
else
  if [ ! -t 0 ]; then
    echo "No TTY for password prompt. Use --password-file /tmp/yahoo-imap-app-pw" >&2
    exit 1
  fi
  if [ -z "$USERNAME" ]; then
    printf 'Yahoo email: '
    read -r USERNAME || true
  else
    printf 'Yahoo email [%s]: ' "$USERNAME"
    read -r REPLY || true
    if [ -n "${REPLY:-}" ]; then
      USERNAME="$REPLY"
    fi
  fi
  printf 'Yahoo IMAP app password: '
  stty -echo 2>/dev/null || true
  read -r YAHOO_APP_PW || YAHOO_APP_PW=""
  stty echo 2>/dev/null || true
  printf '\n'
fi

if [ -z "$USERNAME" ]; then
  echo "Username (Yahoo email) cannot be empty." >&2
  exit 1
fi
if [ -z "$YAHOO_APP_PW" ]; then
  echo "Password cannot be empty." >&2
  exit 1
fi

export YAHOO_APP_PW USERNAME HANDLE NATHAN_URL NATHAN_KEY

RESULT="$(python3 <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

payload = {
    "handle": os.environ["HANDLE"],
    "username": os.environ["USERNAME"],
    "password": os.environ["YAHOO_APP_PW"],
    "notes": (
        "Yahoo IMAP app password for mail-janitor. "
        "Local profile SoT: profiles/<name>/.env MAIL_JANITOR_EMAIL + MAIL_JANITOR_APP_PASSWORD. "
        "URI: imap.mail.yahoo.com:993"
    ),
    "uri": "imap.mail.yahoo.com",
}
req = urllib.request.Request(
    os.environ["NATHAN_URL"].rstrip("/") + "/v1/tools/secrets.store",
    data=json.dumps(payload).encode(),
    headers={
        "Authorization": f"Bearer {os.environ['NATHAN_KEY']}",
        "Content-Type": "application/json",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        body = json.loads(resp.read().decode())
except urllib.error.HTTPError as exc:
    detail = exc.read().decode()[:600]
    print(f"ERR|{exc.code}|{detail}")
    sys.exit(0)
except Exception as exc:
    print(f"ERR|0|{exc}")
    sys.exit(0)

result = body.get("result") if isinstance(body, dict) else None
if not isinstance(result, dict):
    result = body if isinstance(body, dict) else {}
handle = result.get("handle") or os.environ["HANDLE"]
print(f"OK|{handle}|{result.get('username', '')}|{bool(result.get('id'))}")
PY
)"

unset YAHOO_APP_PW

case "$RESULT" in
  OK\|*)
    echo "Stored OK in Vaultwarden (handle ${HANDLE})."
    echo "Verify: fsb do secrets.list   # or GET …/secrets.list — look for ${HANDLE}"
    echo "Next: copy into mail-janitor profile .env (or ask agent to sync from vault)."
    ;;
  ERR\|*)
    CODE="${RESULT#ERR|}"
    CODE="${CODE%%|*}"
    DETAIL="${RESULT#ERR|${CODE}|}"
    echo "secrets.store failed (HTTP ${CODE})." >&2
    echo "${DETAIL}" >&2
    echo "Common fix: restore unlock file on fsb-03 → /opt/stacks/nathan/secrets/vw-master (mode 600)." >&2
    echo "Prefer NATHAN_URL=http://127.0.0.1:9102 on fsb-03." >&2
    exit 1
    ;;
  *)
    echo "Unexpected response: $RESULT" >&2
    exit 1
    ;;
esac

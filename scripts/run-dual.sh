#!/usr/bin/env bash
# Start personalized (8787) + client (8788) Mail Janitor UIs on this host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Personal uses the live profiles tree (yahoo stays private / gitignored).
PERSONAL_PROFILES="${MAIL_JANITOR_PERSONAL_PROFILES:-$ROOT/profiles}"
# Client sessions are ephemeral workspaces (Authentik-gated at NPM).
CLIENT_SESSIONS="${MAIL_JANITOR_SESSIONS_DIR:-$ROOT/deploy/client-sessions}"
PERSONAL_PORT="${MAIL_JANITOR_PERSONAL_PORT:-8787}"
CLIENT_PORT="${MAIL_JANITOR_DEMO_PORT:-${MAIL_JANITOR_CLIENT_PORT:-8788}}"
PROFILE="${MAIL_JANITOR_PROFILE:-yahoo}"

mkdir -p "$CLIENT_SESSIONS" "$ROOT/deploy/logs"
# Symlink _example so ensure_profile_files can seed client workspaces.
if [[ ! -d "$CLIENT_SESSIONS/_example" ]]; then
  ln -sfn "$ROOT/profiles/_example" "$CLIENT_SESSIONS/_example"
fi

if [[ ! -f "$PERSONAL_PROFILES/$PROFILE/config.toml" ]]; then
  echo "Missing $PERSONAL_PROFILES/$PROFILE — create it first" >&2
  exit 1
fi

"$ROOT/.venv/bin/pip" install -q -e "$ROOT"

# Stop prior review UIs (prefer our user; fall back to whatever ss reports).
pkill -u "$(id -un)" -f 'mail-janitor review' 2>/dev/null || true
for port in "$PERSONAL_PORT" "$CLIENT_PORT"; do
  pids=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {print}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u)
  for pid in $pids; do
    kill "$pid" 2>/dev/null || true
  done
done
sleep 1
for port in "$PERSONAL_PORT" "$CLIENT_PORT"; do
  if ss -tln 2>/dev/null | awk -v p=":$port" '$4 ~ p {found=1} END{exit !found}'; then
    echo "Port $port still in use — stop the other owner (often a leftover jonaldo process) and retry." >&2
    exit 1
  fi
done

MAIL_JANITOR_RUN_AS="${MAIL_JANITOR_RUN_AS:-fsb-agent}"
# If not running as the profile-owner service account, try it via runuser when root;
# otherwise require the operator to invoke this script as that user.
if [[ "$(id -un)" != "$MAIL_JANITOR_RUN_AS" ]] && [[ "$(id -un)" != "root" ]]; then
  if id -u "$MAIL_JANITOR_RUN_AS" >/dev/null 2>&1; then
    echo "Re-exec as $MAIL_JANITOR_RUN_AS (owns profile secrets / live review process)…"
    exec sudo -u "$MAIL_JANITOR_RUN_AS" -H bash "$0" "$@"
  fi
fi

RUN_AS="$(id -un)"
run_as() {
  env "$@"
}

run_as MAIL_JANITOR_PROFILES_DIR="$PERSONAL_PROFILES" \
  MAIL_JANITOR_PUBLIC_BASE="${MAIL_JANITOR_PERSONAL_PUBLIC_BASE:-/portal/mail-janitor/app}" \
  MAIL_JANITOR_THEME="${MAIL_JANITOR_PERSONAL_THEME:-fsb}" \
  NATHAN_URL="${NATHAN_URL:-}" \
  NATHAN_API_KEY="${NATHAN_API_KEY:-}" \
  MAIL_JANITOR_NTFY_TOPIC="${MAIL_JANITOR_NTFY_TOPIC:-fsb-nathan}" \
  nohup "$ROOT/.venv/bin/mail-janitor" review -p "$PROFILE" --host 0.0.0.0 --port "$PERSONAL_PORT" \
  >>"$ROOT/deploy/logs/personal.log" 2>&1 &
echo $! >"$ROOT/deploy/logs/personal.pid"

# Client instance: profile name is a placeholder; real workspaces are per Authentik uid.
run_as MAIL_JANITOR_PROFILES_DIR="$CLIENT_SESSIONS" \
  MAIL_JANITOR_SESSIONS_DIR="$CLIENT_SESSIONS" \
  MAIL_JANITOR_PUBLIC_BASE="${MAIL_JANITOR_DEMO_PUBLIC_BASE:-}" \
  MAIL_JANITOR_THEME="${MAIL_JANITOR_DEMO_THEME:-demo}" \
  MAIL_JANITOR_CLIENT_MODE=1 \
  MAIL_JANITOR_SESSION_TTL_HOURS="${MAIL_JANITOR_SESSION_TTL_HOURS:-12}" \
  nohup "$ROOT/.venv/bin/mail-janitor" review -p client --host 0.0.0.0 --port "$CLIENT_PORT" \
  >>"$ROOT/deploy/logs/demo.log" 2>&1 &
echo $! >"$ROOT/deploy/logs/demo.pid"

sleep 2
curl -sf -m 5 "http://127.0.0.1:${PERSONAL_PORT}/api/mission-control/status" | head -c 500 || {
  echo "personal status failed" >&2
  tail -40 "$ROOT/deploy/logs/personal.log" >&2 || true
  exit 1
}
echo
curl -sf -m 5 "http://127.0.0.1:${CLIENT_PORT}/api/mission-control/status" | head -c 500 || {
  echo "client status failed" >&2
  tail -40 "$ROOT/deploy/logs/demo.log" >&2 || true
  exit 1
}
echo
echo "Personal (MC): https://fullstackboston.com/portal/mail-janitor/app/guide"
echo "Client (AK):   https://mail-janitor.fullstackboston.com/guide"
echo "Direct:        http://127.0.0.1:${PERSONAL_PORT}/guide  ·  http://127.0.0.1:${CLIENT_PORT}/guide"

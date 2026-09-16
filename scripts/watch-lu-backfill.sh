#!/usr/bin/env bash
# Live dashboard for list-unsubscribe backfill.
set -euo pipefail
KEY="${HOME}/.config/fsb/agent-ssh/id_ed25519_fsb_agent"
HOST="fsb-agent@100.64.0.5"
STATUS="/tmp/mail-janitor-backfill-lu.status"
LOG="/tmp/mail-janitor-backfill-lu.log"

fmt_secs() {
  local s="${1:-0}"
  if [ "$s" -lt 0 ] 2>/dev/null; then
    echo "—"
    return
  fi
  local h=$((s / 3600)) m=$(((s % 3600) / 60)) sec=$((s % 60))
  if [ "$h" -gt 0 ]; then
    printf "%dh%02dm%02ds" "$h" "$m" "$sec"
  else
    printf "%dm%02ds" "$m" "$sec"
  fi
}

echo "List-Unsubscribe backfill — live progress"
echo "Ctrl-C stops this watcher only (backfill keeps running)."
echo

while true; do
  out=$(ssh -i "$KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 "$HOST" bash -s <<REMOTE
PID=\$(pgrep -f 'mail-janitor backfill-list-unsubscribe -p yahoo' | head -1 || true)
if [ -z "\${PID:-}" ]; then
  echo "proc_state=done"
else
  etime=\$(ps -p "\$PID" -o etime= | tr -d ' ')
  echo "proc_state=running"
  echo "pid=\$PID"
  echo "etime=\$etime"
fi
if [ -f $STATUS ]; then
  echo "---status---"
  cat $STATUS
fi
echo "---db---"
sqlite3 /opt/fsb/data/repos/mail-janitor/profiles/yahoo/mail.db <<'SQL'
SELECT 'db_total=' || count(*) FROM messages;
SELECT 'db_lu_yes=' || count(*) FROM messages WHERE list_unsubscribe=1;
SELECT 'db_lu_no=' || count(*) FROM messages WHERE list_unsubscribe=0;
SQL
echo "---log---"
tail -n 6 $LOG 2>/dev/null || true
REMOTE
) || out="ssh_failed=1"

  # parse key=value lines into shell vars
  checked=""; total=""; pct=""; rate=""; eta_sec=""; elapsed_sec=""
  folder=""; folder_done=""; folder_total=""; lu_found=""; lu_absent=""
  missing=""; errors=""; skipped=""; proc_state=""; etime=""; pid=""
  db_total=""; db_lu_yes=""; db_lu_no=""
  while IFS= read -r line; do
    case "$line" in
      *=*)
        k="${line%%=*}"; v="${line#*=}"
        case "$k" in
          checked|total|pct|lu_found|lu_absent|missing|skipped_already_1|rate_per_sec|elapsed_sec|eta_sec|folder|folder_done|folder_total|errors|proc_state|etime|pid|db_total|db_lu_yes|db_lu_no)
            printf -v "$k" '%s' "$v" 2>/dev/null || true
            # bash nameref-ish for skipped
            if [ "$k" = "skipped_already_1" ]; then skipped="$v"; fi
            if [ "$k" = "rate_per_sec" ]; then rate="$v"; fi
            ;;
        esac
        ;;
    esac
  done <<< "$out"

  clear 2>/dev/null || true
  echo "══════════════════════════════════════════════════"
  echo "  List-Unsubscribe backfill"
  echo "  $(date)"
  echo "══════════════════════════════════════════════════"
  echo
  if [ "${proc_state:-}" = "done" ]; then
    echo "  Process:  FINISHED"
  else
    echo "  Process:  running  pid=${pid:-?}  wall=${etime:-?}"
  fi
  echo
  if [ -n "${total:-}" ] && [ "${total:-0}" != "0" ]; then
    echo "  Progress (this run)"
    echo "    checked     ${checked:-0} / ${total}   (${pct:-0}%)"
    echo "    folder      ${folder:-(n/a)}   ${folder_done:-0} / ${folder_total:-0}"
    echo "    rate        ${rate:-?} msg/s"
    echo "    elapsed     $(fmt_secs "${elapsed_sec:-0}")"
    echo "    ETA         $(fmt_secs "${eta_sec:--1}")"
    echo
    echo "  Findings (this run)"
    echo "    newly flagged (LU yes)   ${lu_found:-0}"
    echo "    confirmed no LU          ${lu_absent:-0}"
    echo "    missing on server        ${missing:-0}"
    echo "    skipped (already LU=1)   ${skipped:-0}"
    echo "    errors                   ${errors:-0}"
  else
    echo "  (waiting for first PROGRESS status file…)"
  fi
  echo
  echo "  Index snapshot (DB)"
  echo "    total=${db_total:-?}   lu_yes=${db_lu_yes:-?}   lu_no=${db_lu_no:-?}"
  echo
  echo "  Recent log"
  echo "$out" | sed -n '/^---log---$/,${/^---log---$/d;p}' | sed 's/^/    /'
  echo
  echo "══════════════════════════════════════════════════"
  echo "  checked/total = messages fetched this run (skips already-flagged)"
  echo "  lu_yes in DB   = cumulative with List-Unsubscribe after updates"
  echo "  ETA            = remaining_this_run / current_rate"
  echo

  if [ "${proc_state:-}" = "done" ]; then
    echo "Backfill finished. Final log:"
    ssh -i "$KEY" -o BatchMode=yes -o IdentitiesOnly=yes "$HOST" "tail -n 40 $LOG" || true
    break
  fi
  sleep 3
done

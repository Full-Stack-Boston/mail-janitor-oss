#!/usr/bin/env bash
# Live dashboard for Insights → rules create (rules.yaml growth).
# Run on fsb-01 (same host as the review UI / profile).
#
#   ./scripts/watch-rules-create.sh
#   START_TOTAL=1470 TARGET_ADDS=2423 ./scripts/watch-rules-create.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES="${RULES:-$ROOT/profiles/yahoo/rules.yaml}"
TARGET_ADDS="${TARGET_ADDS:-2423}"
START_TOTAL="${START_TOTAL:-1470}"
INTERVAL="${INTERVAL:-2}"
UI_PORT="${UI_PORT:-8787}"

fmt_secs() {
  local s="${1:-0}"
  s="${s%.*}"
  if [ -z "$s" ] || ! [ "$s" -ge 0 ] 2>/dev/null; then
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

echo "Rules create watcher — Ctrl-C stops this view only (create keeps running)."
echo "Watching: $RULES"
echo

prev_total=""
prev_ts=""
rate="0"
idle_ticks=0
watcher_t0=$(date +%s)

while true; do
  # Prefer project venv (PyYAML); fall back to counting "- id:" lines.
  PYBIN="$ROOT/.venv/bin/python3"
  [ -x "$PYBIN" ] || PYBIN=python3
  sample=$("$PYBIN" - <<PY
from pathlib import Path
import time, subprocess, socket
p = Path("$RULES")
st = p.stat()
text = p.read_text(encoding="utf-8")
stage = keep = 0
try:
    import yaml
    data = yaml.safe_load(text) or {}
    stage = len(data.get("stage") or [])
    keep = len(data.get("keep") or [])
    total = stage + keep
except Exception:
    total = text.count("\n- id:")
    # crude split: everything before a lone "keep:" section header
    if "\nkeep:\n" in text or text.startswith("keep:\n"):
        pre, _, post = text.partition("\nkeep:\n")
        if text.startswith("keep:\n"):
            stage, keep = 0, text.count("\n- id:")
        else:
            stage = pre.count("\n- id:")
            keep = post.count("\n- id:")
    else:
        stage, keep = total, 0
print(f"stage={stage}")
print(f"keep={keep}")
print(f"total={total}")
print(f"size={st.st_size}")
print(f"mtime_ns={st.st_mtime_ns}")
print(f"ts={time.time()}")
ps = subprocess.getoutput("ps -eo pid,etime,cmd | grep '[m]ail-janitor review' | head -1").strip()
print(f"ui={ps or 'none'}")
sock = socket.socket(); sock.settimeout(0.35)
try:
    sock.connect(("127.0.0.1", int("$UI_PORT")))
    sock.close()
    print("ui_port=accepting")
except Exception:
    print("ui_port=blocked_or_down")
PY
)

  stage=""; keep=""; total=""; size=""; mtime_ns=""; ts=""; ui=""; ui_port=""
  while IFS= read -r line; do
    case "$line" in
      *=*)
        k="${line%%=*}"; v="${line#*=}"
        case "$k" in
          stage|keep|total|size|mtime_ns|ts|ui|ui_port) printf -v "$k" '%s' "$v" ;;
        esac
        ;;
    esac
  done <<< "$sample"

  now=$(date +%s)
  if [ -n "${prev_total:-}" ] && [ -n "${prev_ts:-}" ] && [ -n "${total:-}" ] && [ -n "${ts:-}" ]; then
    dt=$(python3 -c "print(max(0.001, float('$ts')-float('$prev_ts')))")
    dtotal=$((total - prev_total))
    if [ "$dtotal" -gt 0 ]; then
      rate=$(python3 -c "print($dtotal / float('$dt'))")
      idle_ticks=0
    else
      idle_ticks=$((idle_ticks + 1))
      rate=$(python3 -c "r=float('$rate'); print(r if r<=0 else max(0.0, r*0.9))")
    fi
  fi

  target=$((START_TOTAL + TARGET_ADDS))
  done_n=$((total - START_TOTAL))
  if [ "$done_n" -lt 0 ]; then done_n=0; fi
  if [ "$done_n" -gt "$TARGET_ADDS" ]; then done_n=$TARGET_ADDS; fi
  left=$((TARGET_ADDS - done_n))
  pct=$(python3 -c "print(f'{100.0 * $done_n / max(1,$TARGET_ADDS):.1f}')")
  eta_sec=$(python3 -c "r=float('$rate'); print(int($left/r) if r>0.01 else -1)")
  rate_s=$(python3 -c "print(f'{float(\"$rate\"):.2f}')")
  rate_m=$(python3 -c "print(f'{float(\"$rate\")*60:.0f}')")

  # simple progress bar
  bar_w=30
  filled=$(python3 -c "print(int($bar_w * $done_n / max(1,$TARGET_ADDS)))")
  bar=$(python3 -c "f=$filled; w=$bar_w; print('█'*f + '░'*(w-f))")

  clear 2>/dev/null || true
  echo "══════════════════════════════════════════════════"
  echo "  Creating suggestions (rules.yaml)"
  echo "  $(date)"
  echo "══════════════════════════════════════════════════"
  echo
  echo "  [$bar] ${pct}%"
  echo
  echo "  batch:       ${done_n} / ${TARGET_ADDS}"
  echo "  remaining:   ${left}"
  echo "  rate:        ${rate_s}/s  (${rate_m}/min)"
  echo "  ETA:         $(fmt_secs "$eta_sec")"
  echo "  watcher:     $(fmt_secs $((now - watcher_t0)))"
  echo
  echo "  stage/keep:  ${stage} / ${keep}   (total ${total})"
  echo "  file size:   ${size} bytes"
  echo "  start→end:   ${START_TOTAL} → ${target}"
  echo
  echo "  UI process:  ${ui}"
  echo "  UI :${UI_PORT}:   ${ui_port}"
  if [ "$idle_ticks" -ge 8 ]; then
    echo
    echo "  ※ no growth for ~$((idle_ticks * INTERVAL))s — finished or stalled"
  fi
  echo
  echo "Ctrl-C stops watcher only."

  prev_total="$total"
  prev_ts="$ts"
  sleep "$INTERVAL"
done

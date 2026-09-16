"""Human-friendly elapsed / ETA helpers for long-running jobs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def elapsed_seconds(started_at: str | None, *, now: datetime | None = None) -> float | None:
    start = parse_iso(started_at)
    if not start:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - start).total_seconds())


def format_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    try:
        s = int(round(float(seconds)))
    except (TypeError, ValueError):
        return "—"
    if s < 0:
        return "—"
    if s < 60:
        return f"{s}s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{m}m {sec:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def eta_seconds(
    *,
    done: float | int,
    total: float | int | None,
    elapsed_sec: float | None,
    min_done: float = 3.0,
) -> int | None:
    """Estimate seconds remaining from linear rate. None until enough sample."""
    if elapsed_sec is None or elapsed_sec <= 0:
        return None
    try:
        done_f = float(done)
        total_f = float(total) if total is not None else None
    except (TypeError, ValueError):
        return None
    if total_f is None or total_f <= 0 or done_f < min_done:
        return None
    if done_f >= total_f:
        return 0
    rate = done_f / elapsed_sec
    if rate <= 0:
        return None
    return int(round((total_f - done_f) / rate))


def progress_snapshot(
    *,
    done: float | int,
    total: float | int | None,
    started_at: str | None,
    label: str = "items",
    min_done: float = 3.0,
) -> dict[str, Any]:
    """Build a small dict the UI can render without more math."""
    elapsed = elapsed_seconds(started_at)
    total_i = int(total) if total is not None else None
    done_i = int(done)
    eta = eta_seconds(done=done_i, total=total_i, elapsed_sec=elapsed, min_done=min_done)
    pct = None
    if total_i and total_i > 0:
        pct = round(100.0 * min(done_i, total_i) / total_i, 1)
    rate = None
    if elapsed and elapsed > 0 and done_i > 0:
        rate = round(done_i / elapsed, 2)
    parts = []
    if total_i is not None:
        parts.append(f"{done_i:,}/{total_i:,} {label}")
        if pct is not None:
            parts.append(f"{pct}%")
    else:
        parts.append(f"{done_i:,} {label}")
    if rate is not None:
        parts.append(f"{rate}/s")
    parts.append(f"elapsed {format_duration(elapsed)}")
    parts.append(f"ETA {format_duration(eta)}")
    return {
        "done": done_i,
        "total": total_i,
        "pct": pct,
        "elapsed_sec": int(elapsed) if elapsed is not None else None,
        "eta_sec": eta,
        "rate_per_sec": rate,
        "elapsed_human": format_duration(elapsed),
        "eta_human": format_duration(eta),
        "summary": " · ".join(parts),
    }

"""Background scan jobs for the review UI.

Runs the scan in a child *process* so CPU-heavy header work cannot starve the
uvicorn event loop (thread-based scans were wedging HTTP → Cloudflare 524s).
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mail_janitor.config import load_profile
from mail_janitor.db import init_db, message_count
from mail_janitor.notify import notify_job
from mail_janitor.progress import progress_snapshot
from mail_janitor.scan import blank_header_stats, refresh_blank_headers, scan_mailbox


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _status_path_for(profile_name: str) -> Path:
    profile = load_profile(profile_name)
    return Path(profile.db_path).resolve().parent / ".mj_scan_status.json"


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, ensure_ascii=False)
    fd, tmp_name = tempfile.mkstemp(prefix=".mj_scan_", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _read_status(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _idle_status() -> dict[str, Any]:
    return {
        "state": "idle",
        "profile": None,
        "resume": True,
        "started_at": None,
        "finished_at": None,
        "message_count_before": None,
        "message_count_after": None,
        "result": None,
        "error": None,
        "message": None,
        "progress": None,
        "eta": None,
    }


def _enrich(raw: dict[str, Any]) -> dict[str, Any]:
    out = dict(raw)
    if out.get("state") == "running":
        prog = out.get("progress") or {}
        snap = progress_snapshot(
            done=prog.get("uids_done") or 0,
            total=prog.get("uids_planned"),
            started_at=out.get("started_at"),
            label="UIDs",
            min_done=20,
        )
        out["eta"] = snap
        folder = prog.get("folder") or "?"
        phase = prog.get("phase") or ""
        if phase in ("listing_folders", "planned") and not prog.get("uids_planned"):
            out["message"] = (
                f"Planning scan ({folder}) · elapsed {snap['elapsed_human']} "
                f"· ETA after folder inventory"
            )
        else:
            out["message"] = (
                f"Scanning {folder}"
                + (f" ({phase})" if phase else "")
                + f" · {snap['summary']}"
            )
    return out


def _scan_worker(profile_name: str, resume: bool, status_path: str) -> None:
    path = Path(status_path)

    def write_update(**fields: Any) -> None:
        cur = _read_status(path) or _idle_status()
        cur.update(fields)
        _atomic_write(path, cur)

    def heartbeat(**fields: Any) -> None:
        cur = _read_status(path) or _idle_status()
        if cur.get("state") != "running":
            return
        prog = dict(cur.get("progress") or {})
        prog.update(fields)
        prog["updated_at"] = _now()
        cur["progress"] = prog
        _atomic_write(path, cur)

    try:
        profile = load_profile(profile_name)
        conn = init_db(profile.db_path)
        try:
            before = message_count(conn)
        finally:
            conn.close()
        write_update(message_count_before=before, message="Planning folders…")
        result = scan_mailbox(profile, resume=resume, progress_cb=heartbeat)
        repair: dict[str, Any] | None = None
        blanks = blank_header_stats(profile)
        if blanks.get("needs_repair"):
            write_update(
                message=f"Repairing {blanks['blank']} blank From/Subject rows…"
            )
            repair = refresh_blank_headers(profile)
            result = dict(result)
            result["blank_headers"] = blanks
            result["blank_repair"] = repair
        conn = init_db(profile.db_path)
        try:
            after = message_count(conn)
        finally:
            conn.close()
        msg = f"Done · upserted {result.get('messages_upserted', 0)}"
        if repair:
            msg += f" · repaired {repair.get('repaired', 0)} blank headers"
        write_update(
            state="done",
            finished_at=_now(),
            message_count_after=after,
            result=result,
            error=None,
            message=msg,
        )
        notify_job("Mail Janitor scan done", f"{profile_name}: {msg}")
    except Exception as exc:
        write_update(
            state="error",
            finished_at=_now(),
            error=str(exc),
            result={"traceback": traceback.format_exc()[-2000:]},
            message=f"Error: {exc}",
        )
        notify_job(
            "Mail Janitor scan failed",
            f"{profile_name}: {exc}",
            priority=4,
        )


class ScanJobManager:
    """One scan at a time per process; status is mirrored to a JSON file."""

    def __init__(self) -> None:
        self._proc: mp.Process | None = None
        self._status_path: Path | None = None
        self._fallback = _idle_status()

    def _alive(self) -> bool:
        return bool(self._proc and self._proc.is_alive())

    def status(self) -> dict[str, Any]:
        raw: dict[str, Any] | None = None
        if self._status_path:
            raw = _read_status(self._status_path)
        if raw is None:
            raw = dict(self._fallback)

        # Child died without a terminal state → surface as error.
        if self._proc is not None and not self._alive():
            if raw.get("state") == "running":
                exitcode = self._proc.exitcode
                raw = dict(raw)
                raw.update(
                    {
                        "state": "error",
                        "finished_at": _now(),
                        "error": f"Scan process exited unexpectedly (code {exitcode})",
                        "message": f"Error: scan process exited (code {exitcode})",
                    }
                )
                try:
                    _atomic_write(self._status_path, raw)  # type: ignore[arg-type]
                except Exception:
                    pass
                self._fallback = raw
                self._proc = None
            elif raw.get("state") in ("done", "error", "idle"):
                self._fallback = raw
                self._proc = None

        return _enrich(raw)

    def heartbeat(self, **fields: Any) -> None:
        # Kept for API compatibility; worker writes its own heartbeats.
        if not self._status_path:
            return
        cur = _read_status(self._status_path) or _idle_status()
        if cur.get("state") != "running":
            return
        prog = dict(cur.get("progress") or {})
        prog.update(fields)
        prog["updated_at"] = _now()
        cur["progress"] = prog
        _atomic_write(self._status_path, cur)

    def start(self, profile_name: str, resume: bool = True) -> dict[str, Any]:
        if self._alive():
            return {
                "ok": False,
                "error": "A scan is already running. Wait for it to finish.",
                "status": self.status(),
            }

        # Do not touch SQLite here — parent must stay responsive under poll load.
        path = _status_path_for(profile_name)
        initial = {
            "state": "running",
            "profile": profile_name,
            "resume": resume,
            "started_at": _now(),
            "finished_at": None,
            "message_count_before": None,
            "message_count_after": None,
            "result": None,
            "error": None,
            "message": "Planning folders…",
            "progress": {
                "uids_done": 0,
                "uids_planned": None,
                "phase": "listing_folders",
                "folder": "(planning)",
                "updated_at": _now(),
            },
            "eta": None,
        }
        _atomic_write(path, initial)
        self._status_path = path
        self._fallback = initial

        ctx = mp.get_context("spawn")
        proc = ctx.Process(
            target=_scan_worker,
            args=(profile_name, resume, str(path)),
            name=f"mail-janitor-scan-{profile_name}",
            daemon=True,
        )
        proc.start()
        self._proc = proc
        return {"ok": True, "status": self.status()}


SCAN_JOBS = ScanJobManager()

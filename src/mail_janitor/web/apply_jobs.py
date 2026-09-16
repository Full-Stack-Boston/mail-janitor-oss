"""Background apply/undo jobs for the review UI."""

from __future__ import annotations

import threading
import traceback
from datetime import datetime, timezone
from typing import Any, Callable

from mail_janitor.apply import (
    apply_to_kept,
    apply_to_ready,
    ready_to_trash,
    restore_kept_to_inbox,
    undo_from_kept,
    undo_from_ready,
)
from mail_janitor.config import load_profile
from mail_janitor.notify import notify_job
from mail_janitor.progress import progress_snapshot


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApplyJobManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._status: dict[str, Any] = {
            "state": "idle",
            "job": None,
            "started_at": None,
            "finished_at": None,
            "result": None,
            "error": None,
            "message": None,
            "progress": None,
        }

    def heartbeat(self, **fields: Any) -> None:
        """Update live progress while a job runs (safe from worker thread)."""
        with self._lock:
            if self._status.get("state") != "running":
                return
            prog = dict(self._status.get("progress") or {})
            prog.update(fields)
            prog["updated_at"] = _now()
            self._status["progress"] = prog

    def status(self) -> dict[str, Any]:
        with self._lock:
            out = dict(self._status)
        if out.get("state") == "running":
            prog = out.get("progress") or {}
            moved = int(prog.get("moved_this_job") or 0)
            total = prog.get("total_planned")
            if total is None:
                rem = prog.get("remaining_estimate")
                if rem is not None:
                    total = moved + int(rem)
            snap = progress_snapshot(
                done=moved,
                total=total,
                started_at=out.get("started_at"),
                label="moved",
                min_done=5,
            )
            out["eta"] = snap
            folder = prog.get("folder") or "?"
            errors = prog.get("errors_this_job", 0)
            out["message"] = (
                f"Moving in {folder} · {snap['summary']} · errors={errors}"
            )
        return out

    def acknowledge(self) -> dict[str, Any]:
        """No-op kept for API compatibility. Finished jobs stay 'done' with result visible."""
        with self._lock:
            return dict(self._status)

    def is_running(self) -> bool:
        with self._lock:
            return self._status.get("state") == "running"

    def start_apply(self, profile_name: str, confirm: str) -> dict[str, Any]:
        def target() -> dict[str, Any]:
            return apply_to_ready(
                load_profile(profile_name),
                confirm=confirm,
                progress_cb=self.heartbeat,
            )

        return self._start(
            profile_name,
            job="apply",
            message="Starting batched IMAP MOVE…",
            target=target,
        )

    def start_apply_kept(self, profile_name: str, confirm: str) -> dict[str, Any]:
        def target() -> dict[str, Any]:
            return apply_to_kept(
                load_profile(profile_name),
                confirm=confirm,
                progress_cb=self.heartbeat,
            )

        return self._start(
            profile_name,
            job="apply-kept",
            message="Moving kept Inbox mail to intentionally kept folder…",
            target=target,
        )

    def start_restore_kept(self, profile_name: str, confirm: str) -> dict[str, Any]:
        def target() -> dict[str, Any]:
            return restore_kept_to_inbox(
                load_profile(profile_name),
                confirm=confirm,
                progress_cb=self.heartbeat,
                drain_live=True,
            )

        return self._start(
            profile_name,
            job="restore-kept",
            message="Restoring intentionally kept mail to Inbox…",
            target=target,
        )

    def start_to_trash(self, profile_name: str, confirm: str, batch_size: int = 100) -> dict[str, Any]:
        def target() -> dict[str, Any]:
            return ready_to_trash(
                load_profile(profile_name),
                confirm=confirm,
                batch_size=batch_size,
                drain=True,
                progress_cb=self.heartbeat,
            )

        return self._start(
            profile_name,
            job="to-trash",
            message="Moving ready2delete mail to Trash…",
            target=target,
        )

    def _start(
        self,
        profile_name: str,
        *,
        job: str,
        message: str,
        target: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return {
                    "ok": False,
                    "error": "A move job is already running. Wait for it to finish.",
                    "status": dict(self._status),
                }
            self._status = {
                "state": "running",
                "job": job,
                "profile": profile_name,
                "started_at": _now(),
                "finished_at": None,
                "result": None,
                "error": None,
                "message": message,
                "progress": {
                    "moved_this_job": 0,
                    "errors_this_job": 0,
                    "updated_at": _now(),
                },
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(target,),
                name=f"mail-janitor-{job}-{profile_name}",
                daemon=True,
            )
            self._thread.start()
            return {"ok": True, "status": dict(self._status)}

    def _run(self, target: Callable[[], dict[str, Any]]) -> None:
        job = "job"
        with self._lock:
            job = str(self._status.get("job") or "job")
            profile = str(self._status.get("profile") or "")
        try:
            result = target()
            with self._lock:
                self._status.update(
                    {
                        "state": "done",
                        "finished_at": _now(),
                        "result": result,
                        "error": None,
                        "message": "Finished.",
                    }
                )
            moved = (result or {}).get("moved")
            notify_job(
                f"Mail Janitor {job} done",
                f"{profile}: moved {moved}" if moved is not None else f"{profile}: {job} finished",
            )
        except Exception as exc:
            with self._lock:
                self._status.update(
                    {
                        "state": "error",
                        "finished_at": _now(),
                        "error": str(exc),
                        "result": {"traceback": traceback.format_exc()[-2000:]},
                        "message": "Failed.",
                    }
                )
            notify_job(
                f"Mail Janitor {job} failed",
                f"{profile}: {exc}",
                priority=4,
            )


APPLY_JOBS = ApplyJobManager()

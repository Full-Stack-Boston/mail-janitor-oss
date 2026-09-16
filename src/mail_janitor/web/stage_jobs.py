"""Background staging jobs (rule → staged table) for the review UI."""

from __future__ import annotations

import threading
import traceback
from datetime import datetime, timezone
from typing import Any

from mail_janitor.config import load_profile
from mail_janitor.progress import progress_snapshot
from mail_janitor.stage import stage_rules


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StageJobManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._status: dict[str, Any] = {
            "state": "idle",
            "started_at": None,
            "finished_at": None,
            "result": None,
            "error": None,
            "message": None,
            "progress": None,
            "eta": None,
        }

    def _enrich(self, raw: dict[str, Any]) -> dict[str, Any]:
        out = dict(raw)
        if out.get("state") == "running":
            prog = out.get("progress") or {}
            snap = progress_snapshot(
                done=prog.get("rules_done") or 0,
                total=prog.get("rules_total"),
                started_at=out.get("started_at"),
                label="rules",
                min_done=1,
            )
            out["eta"] = snap
            out["message"] = f"Staging · {snap['summary']}"
        return out

    def status(self) -> dict[str, Any]:
        with self._lock:
            raw = dict(self._status)
        return self._enrich(raw)

    def heartbeat(self, **fields: Any) -> None:
        with self._lock:
            if self._status.get("state") != "running":
                return
            prog = dict(self._status.get("progress") or {})
            prog.update(fields)
            prog["updated_at"] = _now()
            self._status["progress"] = prog

    def start(
        self,
        profile_name: str,
        rule_ids: list[str] | None = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raw = dict(self._status)
                return {
                    "ok": False,
                    "error": "A staging job is already running.",
                    "status": self._enrich(raw),
                }
            self._status = {
                "state": "running",
                "profile": profile_name,
                "started_at": _now(),
                "finished_at": None,
                "result": None,
                "error": None,
                "message": "Starting stage…",
                "progress": {
                    "rules_done": 0,
                    "rules_total": len(rule_ids) if rule_ids else None,
                    "updated_at": _now(),
                },
                "eta": None,
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(profile_name, rule_ids, clear),
                name=f"mail-janitor-stage-{profile_name}",
                daemon=True,
            )
            self._thread.start()
            raw = dict(self._status)
        return {"ok": True, "status": self._enrich(raw)}

    def _run(
        self,
        profile_name: str,
        rule_ids: list[str] | None,
        clear: bool,
    ) -> None:
        try:
            profile = load_profile(profile_name)
            result = stage_rules(
                profile,
                rule_ids=rule_ids,
                clear=clear,
                progress_cb=self.heartbeat,
            )
            with self._lock:
                self._status.update(
                    {
                        "state": "done",
                        "finished_at": _now(),
                        "result": result,
                        "error": None,
                        "message": (
                            f"Staged {result.get('staged_included', 0)} messages "
                            f"from {len(result.get('rules_applied') or [])} rules"
                        ),
                    }
                )
        except Exception as exc:
            with self._lock:
                self._status.update(
                    {
                        "state": "error",
                        "finished_at": _now(),
                        "error": str(exc),
                        "result": {"traceback": traceback.format_exc()[-2000:]},
                        "message": f"Error: {exc}",
                    }
                )


STAGE_JOBS = StageJobManager()

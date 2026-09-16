"""Background Insights → rules creation with live ETA."""

from __future__ import annotations

import os
import threading
import traceback
from datetime import datetime, timezone
from typing import Any

from mail_janitor.config import load_profile
from mail_janitor.progress import progress_snapshot
from mail_janitor.rules import rules_from_insight_selections


def _public_base() -> str:
    return (os.environ.get("MAIL_JANITOR_PUBLIC_BASE") or "").rstrip("/")


def _ui(path: str) -> str:
    base = _public_base()
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}" if base else path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InsightsRulesJobManager:
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
                done=prog.get("done") or 0,
                total=prog.get("total"),
                started_at=out.get("started_at"),
                label="picks",
                min_done=5,
            )
            out["eta"] = snap
            phase = prog.get("phase") or ""
            out["message"] = f"Creating rules ({phase}) · {snap['summary']}"
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
        selections: list[dict[str, Any]],
        action: str,
    ) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raw = dict(self._status)
                return {
                    "ok": False,
                    "error": "A rules-creation job is already running.",
                    "status": self._enrich(raw),
                }
            self._status = {
                "state": "running",
                "profile": profile_name,
                "action": action,
                "started_at": _now(),
                "finished_at": None,
                "result": None,
                "error": None,
                "message": "Starting…",
                "progress": {
                    "done": 0,
                    "total": len(selections),
                    "phase": "start",
                    "updated_at": _now(),
                },
                "eta": None,
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(profile_name, selections, action),
                name=f"mail-janitor-insights-rules-{profile_name}",
                daemon=True,
            )
            self._thread.start()
            raw = dict(self._status)
        return {"ok": True, "status": self._enrich(raw)}

    def _run(
        self,
        profile_name: str,
        selections: list[dict[str, Any]],
        action: str,
    ) -> None:
        try:
            profile = load_profile(profile_name)
            created = rules_from_insight_selections(
                profile.rules_path,
                selections,
                action=action,
                progress_cb=self.heartbeat,
            )
            ids = [r.id for r in created]
            # Persist focus batch for /suggestions?focus=session (avoids huge URLs).
            try:
                import json

                (profile.rules_path.parent / "last_focus_batch.json").write_text(
                    json.dumps(ids), encoding="utf-8"
                )
            except OSError:
                pass
            if action == "keep":
                nxt = _ui("/rules")
            else:
                nxt = _ui("/suggestions?focus=session")
            with self._lock:
                self._status.update(
                    {
                        "state": "done",
                        "finished_at": _now(),
                        "result": {
                            "ok": True,
                            "action": action,
                            "created_rule_ids": ids,
                            "created_labels": [r.label for r in created],
                            "created": len(ids),
                            "next": nxt,
                        },
                        "error": None,
                        "message": f"Created {len(ids)} rules",
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


INSIGHTS_RULES_JOBS = InsightsRulesJobManager()

"""Optional operator pings (Nathan ntfy) when long jobs finish."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def notify_job(title: str, message: str, *, priority: int = 3) -> bool:
    """POST to Nathan ntfy.publish when NATHAN_URL + NATHAN_API_KEY are set.

    Silent no-op if unset (local/dev). Never raises.
    """
    base = (os.getenv("NATHAN_URL") or "").rstrip("/")
    key = os.getenv("NATHAN_API_KEY") or ""
    topic = os.getenv("MAIL_JANITOR_NTFY_TOPIC") or "fsb-nathan"
    if not base or not key:
        return False
    payload: dict[str, Any] = {
        "topic": topic,
        "title": title[:120],
        "message": message[:500],
        "priority": priority,
    }
    try:
        req = urllib.request.Request(
            f"{base}/v1/tools/ntfy.publish",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False

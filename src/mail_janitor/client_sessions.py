"""Ephemeral per-Authentik-user workspaces for client mode.

When MAIL_JANITOR_CLIENT_MODE=1:
- Each X-authentik-uid gets an isolated workspace under SESSIONS_DIR
- IMAP credentials live in memory + a 0600 .session-secrets file (for worker processes)
- Workspaces are wiped on End session or after SESSION_TTL_HOURS idle
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mail_janitor.config import REPO_ROOT, ensure_profile_files, _upsert_toml_line
from mail_janitor.providers.packs import PACKS, get_pack

_active_uid: ContextVar[str | None] = ContextVar("mj_client_uid", default=None)
_active_email: ContextVar[str | None] = ContextVar("mj_client_email", default=None)

# uid -> (email, app_password)
_CREDS: dict[str, tuple[str, str]] = {}
_CREDS_LOCK = threading.Lock()

_REAPER_STARTED = False
_REAPER_LOCK = threading.Lock()

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Provider pack hosts always allowed in client mode.
_ALLOWED_IMAP_HOSTS = {
    (p.imap_host or "").strip().lower()
    for p in PACKS.values()
    if (p.imap_host or "").strip()
}


def client_mode() -> bool:
    return (os.environ.get("MAIL_JANITOR_CLIENT_MODE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def session_ttl_seconds() -> float:
    raw = (os.environ.get("MAIL_JANITOR_SESSION_TTL_HOURS") or "12").strip()
    try:
        hours = float(raw)
    except ValueError:
        hours = 12.0
    return max(0.25, hours) * 3600.0


def sessions_dir() -> Path:
    override = (os.environ.get("MAIL_JANITOR_SESSIONS_DIR") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    profiles = (os.environ.get("MAIL_JANITOR_PROFILES_DIR") or "").strip()
    if profiles:
        return Path(profiles).expanduser().resolve()
    return (REPO_ROOT / "deploy" / "client-sessions").resolve()


def safe_uid(uid: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", (uid or "").strip()).strip("-_")
    if not cleaned:
        raise ValueError("Missing Authentik user id")
    if len(cleaned) > 80:
        cleaned = cleaned[:80]
    return cleaned


def workspace_path(uid: str) -> Path:
    return sessions_dir() / safe_uid(uid)


def set_request_identity(uid: str, email: str = "") -> str:
    sid = safe_uid(uid)
    _active_uid.set(sid)
    _active_email.set((email or "").strip())
    return sid


def clear_request_identity() -> None:
    _active_uid.set(None)
    _active_email.set(None)


def current_uid() -> str | None:
    return _active_uid.get()


def current_authentik_email() -> str:
    return (_active_email.get() or "").strip()


def _secrets_path(uid: str) -> Path:
    return workspace_path(uid) / ".session-secrets"


def _activity_path(uid: str) -> Path:
    return workspace_path(uid) / ".last_active"


def touch_activity(uid: str) -> None:
    path = workspace_path(uid)
    path.mkdir(parents=True, exist_ok=True)
    marker = _activity_path(uid)
    marker.write_text(str(time.time()), encoding="utf-8")
    try:
        os.utime(path, None)
    except OSError:
        pass


def ensure_workspace(uid: str) -> Path:
    """Create isolated profile dir for this Authentik user (no durable .env)."""
    sid = safe_uid(uid)
    # Temporarily point ensure_profile_files at sessions root via env already set.
    root = sessions_dir()
    root.mkdir(parents=True, exist_ok=True)
    # ensure_profile_files uses profiles_dir() — client process sets PROFILES_DIR=sessions
    path = ensure_profile_files(sid)
    # Never leave placeholder credentials on disk in client mode.
    env_path = path / ".env"
    if env_path.exists():
        try:
            env_path.unlink()
        except OSError:
            pass
    touch_activity(sid)
    return path


def store_credentials(uid: str, email: str, app_password: str) -> None:
    sid = safe_uid(uid)
    email = email.strip()
    app_password = app_password.strip()
    if not email or "@" not in email:
        raise ValueError("Enter a valid email address")
    if not app_password:
        raise ValueError("App password is required")
    with _CREDS_LOCK:
        _CREDS[sid] = (email, app_password)
    ensure_workspace(sid)
    secrets = _secrets_path(sid)
    secrets.write_text(
        f"MAIL_JANITOR_EMAIL={email}\nMAIL_JANITOR_APP_PASSWORD={app_password}\n",
        encoding="utf-8",
    )
    os.chmod(secrets, 0o600)
    cfg = workspace_path(sid) / "config.toml"
    if cfg.exists():
        text = cfg.read_text(encoding="utf-8")
        text = _upsert_toml_line(text, "email", f'"{email}"')
        cfg.write_text(text, encoding="utf-8")
    touch_activity(sid)


def clear_credentials(uid: str) -> None:
    """Drop in-memory and wipeable session secrets for a client workspace."""
    sid = safe_uid(uid)
    with _CREDS_LOCK:
        _CREDS.pop(sid, None)
    secrets = _secrets_path(sid)
    try:
        secrets.unlink(missing_ok=True)
    except OSError:
        pass


def load_credentials(uid: str) -> tuple[str, str] | None:
    sid = safe_uid(uid)
    with _CREDS_LOCK:
        cached = _CREDS.get(sid)
    if cached:
        return cached
    secrets = _secrets_path(sid)
    if not secrets.is_file():
        return None
    email = ""
    password = ""
    try:
        for line in secrets.read_text(encoding="utf-8").splitlines():
            if line.startswith("MAIL_JANITOR_EMAIL="):
                email = line.split("=", 1)[1].strip()
            elif line.startswith("MAIL_JANITOR_APP_PASSWORD="):
                password = line.split("=", 1)[1].strip()
    except OSError:
        return None
    if email and password:
        with _CREDS_LOCK:
            _CREDS[sid] = (email, password)
        return email, password
    return None


def wipe_session(uid: str) -> dict[str, Any]:
    sid = safe_uid(uid)
    with _CREDS_LOCK:
        _CREDS.pop(sid, None)
    path = workspace_path(sid)
    existed = path.exists()
    if existed:
        shutil.rmtree(path, ignore_errors=True)
    return {"ok": True, "wiped": sid, "existed": existed}


def session_status(uid: str) -> dict[str, Any]:
    sid = safe_uid(uid)
    path = workspace_path(sid)
    creds = load_credentials(sid)
    idle_s = None
    marker = _activity_path(sid)
    if marker.is_file():
        try:
            last = float(marker.read_text(encoding="utf-8").strip())
            idle_s = max(0.0, time.time() - last)
        except (OSError, ValueError):
            idle_s = None
    elif path.exists():
        try:
            idle_s = max(0.0, time.time() - path.stat().st_mtime)
        except OSError:
            idle_s = None
    ttl = session_ttl_seconds()
    return {
        "ok": True,
        "uid": sid,
        "authentik_email": current_authentik_email(),
        "connected": bool(creds),
        "mailbox_email": creds[0] if creds else "",
        "workspace_exists": path.exists(),
        "idle_seconds": idle_s,
        "ttl_seconds": ttl,
        "ttl_hours": ttl / 3600.0,
    }


def reap_idle_sessions(*, now: float | None = None) -> list[str]:
    """Delete workspaces idle longer than TTL. Returns wiped uids."""
    root = sessions_dir()
    if not root.is_dir():
        return []
    ttl = session_ttl_seconds()
    ts = now if now is not None else time.time()
    wiped: list[str] = []
    for child in root.iterdir():
        if not child.is_dir() or child.name.startswith("_") or child.name.startswith("."):
            continue
        marker = child / ".last_active"
        try:
            if marker.is_file():
                last = float(marker.read_text(encoding="utf-8").strip())
            else:
                last = child.stat().st_mtime
        except (OSError, ValueError):
            continue
        if ts - last < ttl:
            continue
        uid = child.name
        wipe_session(uid)
        wiped.append(uid)
    return wiped


def start_reaper_thread() -> None:
    global _REAPER_STARTED
    if not client_mode():
        return
    with _REAPER_LOCK:
        if _REAPER_STARTED:
            return
        _REAPER_STARTED = True

    def _loop() -> None:
        while True:
            try:
                reap_idle_sessions()
            except Exception:
                pass
            time.sleep(300)

    threading.Thread(target=_loop, name="mj-session-reaper", daemon=True).start()


def validate_imap_host(host: str | None, provider_id: str) -> str | None:
    """Return cleaned host or None. Reject private IPs / odd hosts in client mode."""
    pack = get_pack(provider_id)
    cleaned = (host or pack.imap_host or "").strip()
    if not cleaned:
        if pack.id == "imap":
            raise ValueError("IMAP host is required for Other IMAP")
        return None
    lowered = cleaned.lower().rstrip(".")
    # Strip scheme if pasted
    if "://" in lowered:
        parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
        lowered = (parsed.hostname or "").lower()
        cleaned = lowered
    if not lowered:
        raise ValueError("Invalid IMAP host")
    if lowered in _ALLOWED_IMAP_HOSTS:
        return cleaned
    # Block literal IPs in private ranges; allow only public hostnames for custom IMAP
    try:
        addr = ipaddress.ip_address(lowered)
        for net in _PRIVATE_NETS:
            if addr in net:
                raise ValueError("Private or local IMAP hosts are not allowed")
        raise ValueError("Use a hostname for IMAP, not a raw IP")
    except ValueError as exc:
        if "not allowed" in str(exc) or "hostname" in str(exc):
            raise
    # Hostname: reject localhost / internal suffixes
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".local"):
        raise ValueError("Local IMAP hosts are not allowed")
    if pack.id != "imap" and lowered not in _ALLOWED_IMAP_HOSTS:
        # Non-custom providers must use their pack host
        return pack.imap_host
    return cleaned


def parse_authentik_headers(headers: Any) -> tuple[str, str]:
    """Extract uid + email from Authentik forward-auth request headers."""
    def _get(name: str) -> str:
        # Starlette Headers are case-insensitive
        return (headers.get(name) or headers.get(name.lower()) or "").strip()

    uid = (
        _get("x-authentik-uid")
        or _get("X-authentik-uid")
        or _get("x-authentik-sub")
    )
    email = _get("x-authentik-email") or _get("X-authentik-email")
    if not uid:
        raise PermissionError(
            "Sign in via Authentik is required (missing X-authentik-uid)"
        )
    return uid, email

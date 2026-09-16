"""Tests for ephemeral client sessions."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mail_janitor.client_sessions import (
    ensure_workspace,
    load_credentials,
    reap_idle_sessions,
    session_status,
    store_credentials,
    touch_activity,
    validate_imap_host,
    wipe_session,
)


@pytest.fixture()
def sessions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("MAIL_JANITOR_CLIENT_MODE", "1")
    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    monkeypatch.setenv("MAIL_JANITOR_SESSION_TTL_HOURS", "12")
    # Seed _example for ensure_profile_files
    example = tmp_path / "_example"
    example.mkdir()
    (example / "config.toml").write_text('provider = "yahoo"\nemail = "you@example.com"\n', encoding="utf-8")
    (example / "rules.yaml").write_text("keep: []\nstage: []\n", encoding="utf-8")
    (example / "firewall.yaml").write_text("enabled: false\n", encoding="utf-8")
    return tmp_path


def test_store_and_wipe_credentials(sessions: Path) -> None:
    uid = "user-abc"
    ensure_workspace(uid)
    store_credentials(uid, "client@example.com", "secret-app-pass")
    creds = load_credentials(uid)
    assert creds == ("client@example.com", "secret-app-pass")
    secrets = sessions / uid / ".session-secrets"
    assert secrets.is_file()
    assert not (sessions / uid / ".env").exists()
    wipe_session(uid)
    assert not (sessions / uid).exists()
    assert load_credentials(uid) is None


def test_validate_imap_blocks_private(sessions: Path) -> None:
    assert validate_imap_host(None, "yahoo") == "imap.mail.yahoo.com"
    with pytest.raises(ValueError, match="Private|Local|hostname"):
        validate_imap_host("127.0.0.1", "imap")
    with pytest.raises(ValueError, match="Private|Local"):
        validate_imap_host("192.168.1.10", "imap")


def test_reaper_wipes_idle(sessions: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIL_JANITOR_SESSION_TTL_HOURS", "0.0001")  # ~0.36s
    uid = "idle-user"
    ensure_workspace(uid)
    store_credentials(uid, "a@b.co", "x")
    # Force last_active into the past
    marker = sessions / uid / ".last_active"
    marker.write_text("1", encoding="utf-8")
    wiped = reap_idle_sessions()
    assert uid in wiped
    assert not (sessions / uid).exists()


def test_session_status(sessions: Path) -> None:
    uid = "stat-user"
    ensure_workspace(uid)
    touch_activity(uid)
    st = session_status(uid)
    assert st["ok"] is True
    assert st["connected"] is False
    store_credentials(uid, "a@b.co", "pw")
    st2 = session_status(uid)
    assert st2["connected"] is True
    assert st2["mailbox_email"] == "a@b.co"

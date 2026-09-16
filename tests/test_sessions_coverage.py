from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_session_env_identity_and_paths(tmp_path, monkeypatch):
    import mail_janitor.client_sessions as s

    monkeypatch.setenv("MAIL_JANITOR_CLIENT_MODE", "yes")
    assert s.client_mode()
    monkeypatch.setenv("MAIL_JANITOR_SESSION_TTL_HOURS", "bad")
    assert s.session_ttl_seconds() == 12 * 3600
    monkeypatch.setenv("MAIL_JANITOR_SESSION_TTL_HOURS", "0")
    assert s.session_ttl_seconds() == 0.25 * 3600
    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    assert s.sessions_dir() == tmp_path.resolve()
    monkeypatch.delenv("MAIL_JANITOR_SESSIONS_DIR")
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    assert s.sessions_dir() == tmp_path.resolve()
    monkeypatch.delenv("MAIL_JANITOR_PROFILES_DIR")
    assert s.sessions_dir().name == "client-sessions"
    with pytest.raises(ValueError):
        s.safe_uid("")
    assert len(s.safe_uid("x" * 100)) == 80
    assert s.safe_uid(" A/B ") == "A-B"

    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    assert s.workspace_path("u") == tmp_path / "u"
    assert s.set_request_identity("u", " e@x ") == "u"
    assert s.current_uid() == "u" and s.current_authentik_email() == "e@x"
    s.clear_request_identity()
    assert s.current_uid() is None
    assert s._secrets_path("u").name == ".session-secrets"
    assert s._activity_path("u").name == ".last_active"
    s.touch_activity("u")
    assert s._activity_path("u").exists()


def test_workspace_credentials_status_and_wipe(tmp_path, monkeypatch):
    import mail_janitor.client_sessions as s

    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    template = tmp_path / "_example"
    template.mkdir()
    (template / "config.toml").write_text('provider="imap"\n')
    (template / ".env.example").write_text("x")
    (template / "rules.yaml").write_text("keep: []\nstage: []")
    path = s.ensure_workspace("u")
    assert path.exists() and not (path / ".env").exists()
    with pytest.raises(ValueError):
        s.store_credentials("u", "bad", "x")
    with pytest.raises(ValueError):
        s.store_credentials("u", "a@b", "")
    s.store_credentials("u", "a@b", "pw")
    assert s.load_credentials("u") == ("a@b", "pw")
    s._CREDS.clear()
    assert s.load_credentials("u") == ("a@b", "pw")
    assert oct(s._secrets_path("u").stat().st_mode & 0o777) == "0o600"
    status = s.session_status("u")
    assert status["connected"] and status["workspace_exists"]
    s._activity_path("u").write_text("bad")
    assert s.session_status("u")["idle_seconds"] is None
    s._activity_path("u").unlink()
    assert s.session_status("u")["idle_seconds"] is not None
    assert s.wipe_session("u")["existed"]
    assert not s.wipe_session("u")["existed"]
    assert s.load_credentials("none") is None
    # Incomplete secret files are ignored.
    s.ensure_workspace("partial")
    s._secrets_path("partial").write_text("MAIL_JANITOR_EMAIL=a@b\n")
    assert s.load_credentials("partial") is None
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **k: (_ for _ in ()).throw(OSError("read")),
    )
    assert s.load_credentials("partial") is None


def test_reap_start_reaper_and_host_validation(tmp_path, monkeypatch):
    import mail_janitor.client_sessions as s

    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("MAIL_JANITOR_SESSION_TTL_HOURS", "0.25")
    assert s.reap_idle_sessions() == []
    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path / "missing"))
    assert s.reap_idle_sessions() == []
    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    for name in ("old", "_skip", ".hidden"):
        p = tmp_path / name
        p.mkdir()
        (p / ".last_active").write_text("0")
    assert s.reap_idle_sessions(now=10_000)[0] == "old"
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / ".last_active").write_text("bad")
    assert s.reap_idle_sessions(now=10_000) == []
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    os.utime(fresh, (10_000, 10_000))
    assert s.reap_idle_sessions(now=10_001) == []

    monkeypatch.setenv("MAIL_JANITOR_CLIENT_MODE", "0")
    s._REAPER_STARTED = False
    s.start_reaper_thread()
    assert not s._REAPER_STARTED
    monkeypatch.setenv("MAIL_JANITOR_CLIENT_MODE", "1")

    captured = {}

    class T:
        def __init__(self, *a, **k):
            captured["target"] = k.get("target")

        def start(self):
            pass

    monkeypatch.setattr(s.threading, "Thread", T)
    s.start_reaper_thread()
    assert s._REAPER_STARTED
    s.start_reaper_thread()
    monkeypatch.setattr(
        s, "reap_idle_sessions", lambda: (_ for _ in ()).throw(ValueError("x"))
    )
    monkeypatch.setattr(
        s.time,
        "sleep",
        lambda n: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        captured["target"]()

    assert s.validate_imap_host(None, "yahoo")
    assert s.validate_imap_host("https://imap.example.com/x", "imap") == "imap.example.com"
    assert s.validate_imap_host("mail.example.com", "imap") == "mail.example.com"
    with pytest.raises(ValueError):
        s.validate_imap_host("", "imap")
    with pytest.raises(ValueError):
        s.validate_imap_host("://", "imap")
    for host in ("127.0.0.1", "8.8.8.8", "localhost", "thing.local"):
        with pytest.raises(ValueError):
            s.validate_imap_host(host, "imap")
    # Pack providers ignore a custom host.
    assert "yahoo" in s.validate_imap_host("other.example", "yahoo")
    monkeypatch.setattr(
        s,
        "get_pack",
        lambda p: SimpleNamespace(id="yahoo", imap_host=""),
    )
    assert s.validate_imap_host(None, "yahoo") is None


def test_authentik_headers():
    from mail_janitor.client_sessions import parse_authentik_headers

    assert parse_authentik_headers(
        {"x-authentik-uid": "u", "x-authentik-email": "e"}
    ) == ("u", "e")
    assert parse_authentik_headers({"x-authentik-sub": "s"}) == ("s", "")
    with pytest.raises(PermissionError):
        parse_authentik_headers({})


def test_session_best_effort_os_errors(tmp_path, monkeypatch):
    import mail_janitor.client_sessions as s

    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    p = tmp_path / "u"
    p.mkdir()
    (p / ".env").write_text("x")
    monkeypatch.setattr(os, "utime", lambda *a: (_ for _ in ()).throw(OSError("x")))
    s.touch_activity("u")
    monkeypatch.setattr(Path, "unlink", lambda self, *a, **k: (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(s, "ensure_profile_files", lambda sid: p)
    assert s.ensure_workspace("u") == p
    # Restore real unlink for clear_credentials happy path
    monkeypatch.undo()
    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    s.store_credentials("u", "a@x", "pw")
    s.clear_credentials("u")
    assert s.load_credentials("u") is None
    s.store_credentials("u", "a@x", "pw")
    monkeypatch.setattr(
        Path, "unlink", lambda self, *a, **k: (_ for _ in ()).throw(OSError("x"))
    )
    s.clear_credentials("u")


def test_session_status_stat_error(monkeypatch):
    import mail_janitor.client_sessions as s

    class Workspace:
        def exists(self):
            return True

        def stat(self):
            raise OSError("stat")

    class Marker:
        def is_file(self):
            return False

    monkeypatch.setattr(s, "workspace_path", lambda uid: Workspace())
    monkeypatch.setattr(s, "_activity_path", lambda uid: Marker())
    monkeypatch.setattr(s, "load_credentials", lambda uid: None)
    assert s.session_status("u")["idle_seconds"] is None

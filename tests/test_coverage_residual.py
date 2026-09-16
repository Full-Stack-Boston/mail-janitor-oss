"""Final residual coverage for remaining uncovered statements."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from mail_janitor.config import Profile
from mail_janitor.db import init_db, upsert_message
from mail_janitor.firewall_policy import Decision


@pytest.fixture
def profile(tmp_path: Path) -> Profile:
    (tmp_path / "rules.yaml").write_text("keep: []\nstage: []\n")
    (tmp_path / "firewall.yaml").write_text(
        "enabled: true\nwatch_folder: Inbox\nquarantine_folder: Quarantine\n"
        "poll_seconds: 0\nheuristic_quarantine: false\nallow: []\nblock: []\n"
    )
    return Profile(
        name="p",
        path=tmp_path,
        provider="imap",
        email="e@x",
        imap_host="h",
        imap_port=993,
        imap_ssl=True,
        app_password="pw",
        scan_batch_size=2,
        move_batch_size=2,
    )


def test_config_load_dotenv_when_env_exists(tmp_path, monkeypatch):
    import mail_janitor.config as config

    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path))
    monkeypatch.delenv("MAIL_JANITOR_CLIENT_MODE", raising=False)
    monkeypatch.delenv("MAIL_JANITOR_EMAIL", raising=False)
    monkeypatch.delenv("MAIL_JANITOR_APP_PASSWORD", raising=False)
    root = tmp_path / "p"
    root.mkdir()
    (root / "config.toml").write_text(
        'provider="imap"\nemail=""\nimap_host="h"\n', encoding="utf-8"
    )
    (root / ".env").write_text(
        "MAIL_JANITOR_EMAIL=fromenv@x.com\nMAIL_JANITOR_APP_PASSWORD=secret\n",
        encoding="utf-8",
    )
    loaded = []

    def fake_load(path, override=False):
        loaded.append((Path(path), override))
        monkeypatch.setenv("MAIL_JANITOR_EMAIL", "fromenv@x.com")
        monkeypatch.setenv("MAIL_JANITOR_APP_PASSWORD", "secret")

    monkeypatch.setattr(config, "load_dotenv", fake_load)
    profile = config.load_profile("p")
    assert profile.email == "fromenv@x.com"
    assert loaded and loaded[0][1] is True


def test_client_sessions_idle_stat_oserror_and_missing_root(tmp_path, monkeypatch):
    import mail_janitor.client_sessions as s

    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path))
    sid = "nostat"
    path = tmp_path / sid
    path.mkdir()
    real_stat = Path.stat
    real_exists = Path.exists

    def fake_exists(self):
        if self == path:
            return True
        return real_exists(self)

    def fake_stat(self, *a, **k):
        if self == path:
            raise OSError("gone")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "stat", fake_stat)
    assert s.session_status(sid)["idle_seconds"] is None
    monkeypatch.undo()

    monkeypatch.setenv("MAIL_JANITOR_SESSIONS_DIR", str(tmp_path / "missing-root"))
    assert s.reap_idle_sessions() == []


def test_discover_build_triage_score_update(profile, monkeypatch):
    import mail_janitor.discover as d

    conn = init_db(profile.db_path)
    for i, (subj, size) in enumerate(
        [("first", 10), ("better", 20), ("keep lean", 5)], start=1
    ):
        upsert_message(
            conn,
            {
                "folder": "Inbox",
                "uid": i,
                "message_id": f"m{i}",
                "from_addr": "a@x.com",
                "from_domain": "x.com",
                "subject": subj,
                "date_ts": 100 + i,
                "size": size,
            },
        )
    conn.commit()

    scores = [
        {"score": 5, "flags": [], "confidence": "uncertain"},
        {"score": 1, "flags": ["keep"], "confidence": "uncertain"},
        {"score": 2, "flags": [], "confidence": "keep"},
    ]
    monkeypatch.setattr(d, "score_message", lambda msg: scores.pop(0))
    out = d.build_triage(conn, "1=1", [], self_email="")
    conn.close()
    assert any(k.get("confidence") == "keep" for k in out["likely_keep"])


def test_firewall_uidvalidity_reset_empty_exists_and_missing_row(profile, monkeypatch):
    import mail_janitor.firewall as fw

    cfg = SimpleNamespace(
        enabled=True,
        watch_folder="Inbox",
        quarantine_folder="Quarantine",
        poll_seconds=0,
        heuristic_quarantine=False,
        allow=[],
        block=[],
    )
    monkeypatch.setattr(fw, "load_firewall", lambda *a, **k: cfg)
    monkeypatch.setattr(fw, "firewall_path", lambda p: p.path / "firewall.yaml")

    client = MagicMock()
    client.ensure_folder = MagicMock()
    client.select.return_value = (0, 99)
    client.uid_search_all_above.return_value = [5]
    client.fetch_headers.return_value = []
    client.close = MagicMock()
    provider = MagicMock()
    provider.connect.return_value = client
    monkeypatch.setattr(fw, "get_provider", lambda n: provider)
    monkeypatch.setattr(fw, "with_backoff", lambda fn: fn())
    monkeypatch.setattr(fw, "get_firewall_progress", lambda *a, **k: (10, 1))
    monkeypatch.setattr(fw, "set_firewall_progress", lambda *a, **k: None)
    monkeypatch.setattr(fw, "audit_log", lambda *a, **k: None)
    assert fw.process_once(profile)["ok"] is True

    client.select.return_value = (2, 1)
    client.uid_search_all_above.return_value = [1, 2]
    client.fetch_headers.return_value = []
    monkeypatch.setattr(fw, "get_firewall_progress", lambda *a, **k: (0, 1))
    monkeypatch.setattr(
        fw, "evaluate_message", lambda msg, c: Decision("pass", "ok")
    )
    assert fw.process_once(profile, dry_run=True)["ok"] is True

    calls = {"n": 0}

    def once(*a, **k):
        calls["n"] += 1
        return {"ok": True, "n": calls["n"]}

    monkeypatch.setattr(fw, "process_once", once)
    monkeypatch.setattr(fw.time, "sleep", lambda n: None)
    last = fw.watch_loop(profile, once=False, max_iterations=2, dry_run=True)
    assert last["n"] == 2


def test_cli_firewall_watch_non_dry_run_sleeps(monkeypatch, tmp_path):
    import mail_janitor.cli as cli
    import mail_janitor.firewall as fw
    import mail_janitor.firewall_policy as policy

    fake = SimpleNamespace(
        name="p",
        path=tmp_path,
        email="a@x",
        provider="imap",
        rules_path=tmp_path / "rules.yaml",
        firewall_path=tmp_path / "firewall.yaml",
    )
    (tmp_path / "firewall.yaml").write_text("enabled: true\n")
    monkeypatch.setattr(cli, "load_profile", lambda n: fake)
    monkeypatch.setattr(
        policy,
        "load_firewall",
        lambda p: SimpleNamespace(
            watch_folder="Inbox",
            quarantine_folder="Q",
            poll_seconds=0,
            heuristic_quarantine=False,
        ),
    )
    slept = []

    def sleep(n):
        slept.append(n)
        raise KeyboardInterrupt()

    import time as time_mod

    monkeypatch.setattr(time_mod, "sleep", sleep)
    monkeypatch.setattr(fw, "process_once", lambda *a, **k: {"ok": True})
    out = CliRunner().invoke(cli.main, ["firewall", "watch", "-p", "p"])
    assert "Stopped" in out.output
    assert slept


def test_apply_move_batch_conn_error_on_second_retry(profile, monkeypatch):
    import mail_janitor.apply as apply

    errors: list = []
    conn = init_db(profile.db_path)
    row = {
        "folder": "Inbox",
        "uid": 1,
        "message_id": "m",
        "from_addr": "a@x",
        "subject": "s",
        "date_ts": 1,
        "size": 2,
        "rule_id": "r",
    }
    client = MagicMock()

    class BatchErr(Exception):
        pass

    class ConnErr(OSError):
        pass

    state = {"n": 0}

    def move_uids(uids, dest):
        raise BatchErr("NO")

    def move_uid(uid, dest):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("temp fail")
        raise ConnErr("connection reset")

    client.move_uids = move_uids
    client.move_uid = move_uid
    monkeypatch.setattr(apply, "with_backoff", lambda fn, **k: fn())
    monkeypatch.setattr(apply.time, "sleep", lambda n: None)
    monkeypatch.setattr(apply, "_is_conn_error", lambda e: isinstance(e, ConnErr))
    monkeypatch.setattr(apply, "audit_log", lambda *a, **k: None)
    monkeypatch.setattr(apply, "_record_move", lambda *a, **k: None)

    moved, err = apply._move_batch(
        client, profile, conn, "Inbox", [row], "ready2delete", errors
    )
    assert isinstance(err, ConnErr)
    conn.close()


def test_apply_reconnect_fail_swallowed_after_conn_err2(profile, monkeypatch):
    import mail_janitor.apply as apply

    rows = [
        {
            "folder": "Inbox",
            "uid": i,
            "message_id": f"m{i}",
            "from_addr": "a@x",
            "subject": f"s{i}",
            "date_ts": i,
            "size": 2,
            "rule_id": "r",
        }
        for i in range(1, 4)
    ]

    class ConnErr(OSError):
        pass

    move_calls = {"n": 0}

    def move_batch(*args, **kwargs):
        move_calls["n"] += 1
        if move_calls["n"] <= 2:
            return 0, ConnErr("reset")
        return len(args[4]), None

    monkeypatch.setattr(apply, "_move_batch", move_batch)
    monkeypatch.setattr(apply, "with_backoff", lambda fn, **k: fn())
    monkeypatch.setattr(apply, "audit_log", lambda *a, **k: None)
    monkeypatch.setattr(apply, "_is_conn_error", lambda e: True)

    connects = {"n": 0}

    def connect(p):
        connects["n"] += 1
        c = MagicMock()
        c.ensure_folder = MagicMock()
        c.close = MagicMock()
        if connects["n"] >= 3:
            c.select.side_effect = RuntimeError("reconnect dead")
        else:
            c.select.return_value = (3, 1)
        return c

    monkeypatch.setattr(
        apply, "get_provider", lambda n: SimpleNamespace(connect=connect)
    )

    out = apply._apply_rows_to_folder(
        profile,
        rows,
        "ready2delete",
        preflight={"ok": True},
    )
    assert out["errors"]
    assert connects["n"] >= 3

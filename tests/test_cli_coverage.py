from __future__ import annotations

import runpy
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import mail_janitor.cli as cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def fake_profile(tmp_path):
    p = SimpleNamespace(
        name="p",
        path=tmp_path,
        email="a@example.com",
        provider="imap",
        rules_path=tmp_path / "rules.yaml",
        firewall_path=tmp_path / "firewall.yaml",
    )
    p.rules_path.write_text("keep: []\nstage: []\n")
    return p


def test_profiles_and_init_commands(runner, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "list_profiles", lambda: [])
    assert "No profiles" in runner.invoke(cli.main, ["profiles"]).output
    monkeypatch.setattr(cli, "list_profiles", lambda: ["a", "b"])
    out = runner.invoke(cli.main, ["profiles"])
    assert out.exit_code == 0 and "a\nb" in out.output
    monkeypatch.setattr(cli, "ensure_profile_files", lambda n: tmp_path / n)
    out = runner.invoke(cli.main, ["init-profile", "x"])
    assert out.exit_code == 0 and "Created" in out.output


def test_data_commands(runner, monkeypatch, fake_profile):
    monkeypatch.setattr(cli, "load_profile", lambda n: fake_profile)
    funcs = {
        "scan_mailbox": {"messages_upserted": 1},
        "backfill_list_unsubscribe": {"checked": 1},
        "refresh_blank_headers": {"repaired": 1},
        "discover": {"senders": []},
        "preview_all_stage_rules": {"rules": []},
        "stage_rules": {"staged": 1},
        "preflight_staged": {"count": 1},
        "preflight_kept_inbox": {"count": 1},
        "apply_to_kept": {"moved": 1},
        "apply_to_ready": {"moved": 1},
        "undo_from_ready": {"restored": 1},
        "undo_from_kept": {"restored": 1},
        "restore_kept_to_inbox": {"restored": 2},
        "ready_to_trash": {"moved_to_trash": 1},
        "preflight_end_stage": {"kept_count": 1, "ready_count": 2},
        "list_moves": [],
    }
    for name, result in funcs.items():
        monkeypatch.setattr(cli, name, lambda *a, _r=result, **k: _r)
    monkeypatch.setattr(cli, "clear_staged", lambda *a: None)

    cases = [
        ["scan", "-p", "p"],
        ["scan", "-p", "p", "--no-resume"],
        ["backfill-list-unsubscribe", "-p", "p"],
        ["refresh-blank-headers", "-p", "p"],
        ["discover", "-p", "p", "--top", "2"],
        ["preview", "-p", "p"],
        ["stage", "-p", "p", "--rule", "r", "--clear"],
        ["clear-staged", "-p", "p", "--yes"],
        ["preflight", "-p", "p"],
        ["preflight-kept", "-p", "p"],
        ["apply-kept", "-p", "p", "--confirm", "x", "--limit", "1"],
        ["apply", "-p", "p", "--confirm", "x", "--limit", "1"],
        ["undo", "-p", "p", "--confirm", "x", "--limit", "1"],
        ["undo-kept", "-p", "p", "--confirm", "x", "--limit", "1"],
        ["restore-kept", "-p", "p", "--confirm", "x", "--limit", "1", "--no-live-drain"],
        ["to-trash", "-p", "p", "--confirm", "x", "--batch-size", "1"],
        ["to-trash", "-p", "p", "--confirm", "x", "--batch-size", "1", "--all"],
        ["end-stage", "-p", "p"],
        ["moves", "-p", "p"],
        ["moves", "-p", "p", "--all"],
    ]
    for args in cases:
        out = runner.invoke(cli.main, args)
        assert out.exit_code == 0, (args, out.output, out.exception)


def test_preview_archive_rules_review(runner, monkeypatch, fake_profile):
    monkeypatch.setattr(cli, "load_profile", lambda n: fake_profile)
    rule = SimpleNamespace(id="r")
    ruleset = SimpleNamespace(
        get_stage_rule=lambda n: rule if n == "r" else None,
        keep=[SimpleNamespace(raw={"id": "k"})],
        stage=[SimpleNamespace(raw={"id": "s"})],
    )
    monkeypatch.setattr(cli, "load_rules", lambda p: ruleset)
    monkeypatch.setattr(cli, "preview_rule", lambda *a: {"ok": 1})
    assert runner.invoke(cli.main, ["preview", "-p", "p", "--rule", "r"]).exit_code == 0
    out = runner.invoke(cli.main, ["preview", "-p", "p", "--rule", "bad"])
    assert out.exit_code != 0 and "Unknown" in out.output

    import mail_janitor.rules as rules
    monkeypatch.setattr(rules, "archive_dormant_stage_rules", lambda p: {"archived": 1})
    assert runner.invoke(cli.main, ["archive-dormant-stage", "-p", "p"]).exit_code == 0
    assert runner.invoke(cli.main, ["rules-show", "-p", "p"]).exit_code == 0

    import mail_janitor.client_sessions as sessions
    import mail_janitor.web.app as web
    monkeypatch.setattr(sessions, "client_mode", lambda: False)
    monkeypatch.setattr(web, "run_server", lambda *a, **k: None)
    assert runner.invoke(cli.main, ["review", "-p", "p"]).exit_code == 0
    monkeypatch.setattr(sessions, "client_mode", lambda: True)
    assert runner.invoke(cli.main, ["review", "-p", "p"]).exit_code == 0


def test_firewall_commands(runner, monkeypatch, fake_profile):
    monkeypatch.setattr(cli, "load_profile", lambda n: fake_profile)
    import mail_janitor.firewall as fw
    import mail_janitor.firewall_policy as pol

    monkeypatch.setattr(fw, "firewall_status", lambda p: {"enabled": True})
    monkeypatch.setattr(fw, "process_once", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(fw, "list_quarantine", lambda *a, **k: [])
    monkeypatch.setattr(fw, "release_quarantine", lambda *a, **k: {"restored": 1})
    monkeypatch.setattr(
        pol,
        "load_firewall",
        lambda p: SimpleNamespace(
            watch_folder="Inbox",
            quarantine_folder="Q",
            poll_seconds=0,
            heuristic_quarantine=False,
        ),
    )
    made = SimpleNamespace(id="r", from_address="a@x", from_domain="x")
    monkeypatch.setattr(pol, "add_allow_sender", lambda *a: made)
    monkeypatch.setattr(pol, "add_block_sender", lambda *a: made)
    monkeypatch.setattr(pol, "add_block_domain", lambda *a: made)

    cases = [
        ["firewall", "status", "-p", "p"],
        ["firewall", "once", "-p", "p", "--dry-run"],
        ["firewall", "watch", "-p", "p", "--dry-run"],
        ["firewall", "list", "-p", "p", "--limit", "2"],
        ["firewall", "allow", "-p", "p", "a@x"],
        ["firewall", "block", "-p", "p", "a@x"],
        ["firewall", "block", "-p", "p", "x", "--domain"],
        ["firewall", "release", "-p", "p", "--id", "1"],
        ["firewall", "release", "-p", "p", "--limit", "1"],
    ]
    for args in cases:
        out = runner.invoke(cli.main, args)
        assert out.exit_code == 0, (args, out.output, out.exception)
    assert runner.invoke(cli.main, ["firewall", "release", "-p", "p"]).exit_code != 0

    # Keyboard interrupt arm of watch.
    monkeypatch.setattr(
        fw, "process_once", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    assert "Stopped" in runner.invoke(cli.main, ["firewall", "watch", "-p", "p"]).output


def test_main_module_entrypoint(monkeypatch):
    monkeypatch.setattr("sys.argv", ["mail_janitor", "--help"])
    with pytest.raises(SystemExit):
        runpy.run_module("mail_janitor.__main__", run_name="__main__")
    monkeypatch.setattr("sys.argv", ["mail_janitor.cli", "--help"])
    with pytest.raises(SystemExit):
        runpy.run_module("mail_janitor.cli", run_name="__main__")


def test_firewall_watch_keyboard_direct(monkeypatch, fake_profile):
    import mail_janitor.firewall as fw
    import mail_janitor.firewall_policy as policy

    monkeypatch.setattr(cli, "load_profile", lambda n: fake_profile)
    monkeypatch.setattr(
        policy,
        "load_firewall",
        lambda p: SimpleNamespace(
            watch_folder="Inbox",
            quarantine_folder="Q",
            poll_seconds=1,
            heuristic_quarantine=False,
        ),
    )
    monkeypatch.setattr(
        fw,
        "process_once",
        lambda *a, **k: {"ok": True},
    )
    import time

    monkeypatch.setattr(
        time, "sleep", lambda n: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    cli.firewall_watch_cmd.callback("p", False)

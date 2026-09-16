"""Apply-to-kept preflight and inbox-only staging."""

from pathlib import Path
import time

from mail_janitor.apply import preflight_kept_inbox
from mail_janitor.config import Profile
from mail_janitor.db import init_db, upsert_message
from mail_janitor.rules import add_keep_rule, add_stage_rule
from mail_janitor.stage import stage_rules


def _profile(tmp_path: Path) -> Profile:
    prof_dir = tmp_path / "yahoo"
    prof_dir.mkdir()
    (prof_dir / "rules.yaml").write_text("keep: []\nstage: []\n", encoding="utf-8")
    return Profile(
        name="yahoo",
        path=prof_dir,
        provider="yahoo",
        email="me@yahoo.com",
        imap_host="x",
        imap_port=993,
        imap_ssl=True,
        inbox_folder="Inbox",
        kept_folder="Intentionally Kept",
        stage_inbox_only=True,
    )


def _seed(conn, **kw):
    upsert_message(
        conn,
        {
            "folder": kw.get("folder", "Inbox"),
            "uid": kw.get("uid", 1),
            "message_id": kw.get("message_id", f"<{kw.get('uid', 1)}>"),
            "from_addr": kw["from_addr"],
            "from_domain": kw["from_domain"],
            "subject": kw.get("subject", "hi"),
            "date_ts": kw.get("date_ts", int(time.time())),
            "date_raw": "",
            "size": 100,
            "flags": "",
            "list_unsubscribe": 0,
            "scanned_at": "",
        },
    )


def test_preflight_kept_inbox_counts_inbox_only(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="friend@gmail.com", from_domain="gmail.com", folder="Inbox")
    _seed(conn, uid=2, from_addr="friend@gmail.com", from_domain="gmail.com", folder="Sent")
    conn.commit()
    conn.close()

    add_keep_rule(
        p.rules_path,
        {"id": "keep-gmail-com", "label": "gmail", "from_domain": "gmail.com"},
    )
    pre = preflight_kept_inbox(p)
    assert pre["count"] == 1
    assert pre["dest_folder"] == "Intentionally Kept"
    assert pre["confirm_phrase"] == "MOVE TO INTENTIONALLY KEPT"


def test_stage_inbox_only_skips_other_folders(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="spam@x.com", from_domain="x.com", folder="Inbox")
    _seed(conn, uid=2, from_addr="spam@x.com", from_domain="x.com", folder="Sent")
    conn.commit()
    conn.close()

    add_stage_rule(
        p.rules_path,
        {"id": "stage-x-com", "label": "x", "from_domain": "x.com"},
    )
    stage_rules(p)
    conn = init_db(p.db_path)
    cnt = conn.execute("SELECT COUNT(*) FROM staged").fetchone()[0]
    conn.close()
    assert cnt == 1


def test_preview_respects_stage_inbox_only(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="spam@x.com", from_domain="x.com", folder="Inbox")
    _seed(conn, uid=2, from_addr="spam@x.com", from_domain="x.com", folder="Sent")
    conn.commit()
    conn.close()

    from mail_janitor.discover import preview_rule_with_ruleset
    from mail_janitor.rules import Rule, RuleSet, add_stage_rule

    add_stage_rule(
        p.rules_path,
        {"id": "stage-x-com", "label": "x", "from_domain": "x.com"},
    )
    rule = Rule.from_dict({"id": "stage-x-com", "from_domain": "x.com"}, "stage")
    all_folders = preview_rule_with_ruleset(
        p.db_path, rule, RuleSet(), sample_n=0, include_samples=False
    )
    inbox_only = preview_rule_with_ruleset(
        p.db_path, rule, RuleSet(), sample_n=0, include_samples=False, profile=p
    )
    assert all_folders["match_count"] == 2
    assert inbox_only["match_count"] == 1


def test_stage_folders_multi_folder(tmp_path: Path):
    p = _profile(tmp_path)
    p.stage_folders = ["Inbox", "Sent"]
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="spam@x.com", from_domain="x.com", folder="Inbox")
    _seed(conn, uid=2, from_addr="spam@x.com", from_domain="x.com", folder="Sent")
    _seed(conn, uid=3, from_addr="spam@x.com", from_domain="x.com", folder="Bulk")
    conn.commit()
    conn.close()

    add_stage_rule(
        p.rules_path,
        {"id": "stage-x-com", "label": "x", "from_domain": "x.com"},
    )
    stage_rules(p)
    conn = init_db(p.db_path)
    cnt = conn.execute("SELECT COUNT(*) FROM staged").fetchone()[0]
    conn.close()
    assert cnt == 2
    assert p.stage_scope_label() == "Inbox, Sent"


def test_save_stage_folders_writes_config(tmp_path: Path):
    from mail_janitor.config import save_stage_folders

    p = _profile(tmp_path)
    (p.path / "config.toml").write_text(
        "email = \"me@yahoo.com\"\nstage_inbox_only = true\n",
        encoding="utf-8",
    )
    save_stage_folders(p, ["Inbox", "Sent"])
    text = (p.path / "config.toml").read_text(encoding="utf-8")
    assert 'stage_folders = ["Inbox", "Sent"]' in text

    save_stage_folders(p, None)
    text = (p.path / "config.toml").read_text(encoding="utf-8")
    assert "stage_folders" not in text
    assert "stage_inbox_only = false" in text

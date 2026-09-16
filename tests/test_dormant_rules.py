"""Dormant stage rule archive + keep exclusion compile once."""

from pathlib import Path
import time

from mail_janitor.config import Profile
from mail_janitor.db import init_db, upsert_message
from mail_janitor.rules import (
    Rule,
    RuleSet,
    active_stage_rules,
    archive_dormant_stage_rules,
    load_rules,
    save_rules,
)
from mail_janitor.stage import stage_rules


def _profile(tmp_path: Path) -> Profile:
    prof = tmp_path / "p"
    prof.mkdir()
    (prof / "rules.yaml").write_text("keep: []\nstage: []\n", encoding="utf-8")
    return Profile(
        name="p",
        path=prof,
        provider="yahoo",
        email="you@example.com",
        imap_host="x",
        imap_port=993,
        imap_ssl=True,
        stage_inbox_only=True,
    )


def test_archive_dormant_stage_rules(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 1,
            "message_id": "<1>",
            "from_addr": "a@x.com",
            "from_domain": "x.com",
            "subject": "hi",
            "date_ts": int(time.time()),
            "date_raw": "",
            "size": 10,
            "flags": "",
            "list_unsubscribe": 0,
            "scanned_at": "",
        },
    )
    conn.commit()
    conn.close()

    rs = RuleSet(
        stage=[
            Rule.from_dict({"id": "hit", "from_domain": "x.com"}, "stage"),
            Rule.from_dict({"id": "miss", "from_domain": "zzz.invalid"}, "stage"),
        ]
    )
    save_rules(p.rules_path, rs)
    out = archive_dormant_stage_rules(p)
    assert out["archived"] == 1
    assert "miss" in out["archived_ids"]
    loaded = load_rules(p.rules_path)
    assert loaded.get_stage_rule("miss").active is False
    assert loaded.get_stage_rule("hit").active is True
    assert [r.id for r in active_stage_rules(loaded)] == ["hit"]


def test_stage_skips_inactive_unless_explicit(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 1,
            "message_id": "<1>",
            "from_addr": "a@x.com",
            "from_domain": "x.com",
            "subject": "hi",
            "date_ts": int(time.time()),
            "date_raw": "",
            "size": 10,
            "flags": "",
            "list_unsubscribe": 0,
            "scanned_at": "",
        },
    )
    conn.commit()
    conn.close()
    rs = RuleSet(
        stage=[
            Rule.from_dict({"id": "active-x", "from_domain": "x.com"}, "stage"),
            Rule.from_dict({"id": "dormant-x", "from_domain": "x.com", "active": False}, "stage"),
        ]
    )
    save_rules(p.rules_path, rs)
    # Default stage only active rules — still stages once (same messages)
    result = stage_rules(p, clear=True)
    assert "active-x" in result["rules_applied"]
    assert "dormant-x" not in result["rules_applied"]

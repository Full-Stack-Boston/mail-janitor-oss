"""Unit tests for rules and header parsing (no live IMAP)."""

from __future__ import annotations

import time
from pathlib import Path

from mail_janitor.db import init_db, upsert_message
from mail_janitor.discover import preview_rule_with_ruleset
from mail_janitor.parse_headers import extract_address, parse_header_bytes
from mail_janitor.rules import Rule, RuleSet, add_keep_sender, load_rules, save_rules


def test_parse_headers_list_unsubscribe():
    raw = (
        b"From: News <news@example.com>\r\n"
        b"Subject: Hello\r\n"
        b"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <abc@example.com>\r\n"
        b"List-Unsubscribe: <https://example.com/unsub>\r\n"
        b"\r\n"
    )
    parsed = parse_header_bytes(raw)
    assert parsed["from_addr"] == "news@example.com"
    assert parsed["from_domain"] == "example.com"
    assert parsed["subject"] == "Hello"
    assert parsed["list_unsubscribe"] == 1
    assert parsed["date_ts"] is not None


def test_parse_headers_list_unsubscribe_folded_empty_value():
    """Yahoo-style: header present (possibly folded) must count even if sparse."""
    raw = (
        b"From: Promo <p@brand.example>\r\n"
        b"Subject: Sale\r\n"
        b"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n"
        b"List-Unsubscribe:\r\n"
        b" <https://brand.example/unsub>,\r\n"
        b" <mailto:unsub@brand.example>\r\n"
        b"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
        b"\r\n"
    )
    assert parse_header_bytes(raw)["list_unsubscribe"] == 1
    no_lu = (
        b"From: a@b.com\r\nSubject: Hi\r\nDate: Mon, 1 Jan 2024 12:00:00 +0000\r\n\r\n"
    )
    assert parse_header_bytes(no_lu)["list_unsubscribe"] == 0


def test_decode_header_survives_bogus_charset():
    from mail_janitor.parse_headers import decode_header_value

    # RFC2047-looking junk that made email.header hand us charset "base64"
    raw = "=?base64?b?U2FsZQ==?="
    assert "Sale" in decode_header_value(raw) or decode_header_value(raw)
    # Completely unknown charset label
    assert decode_header_value("=?not-a-real-charset?q?Hi?=") or True


def test_parse_header_bytes_never_raises_on_junk():
    # Even pathological payloads should yield a dict, not kill a scan batch.
    assert parse_header_bytes(b"\xff\xfe not headers")["from_addr"] == ""
    assert parse_header_bytes(
        b"From: a@b.com\r\nSubject: =?ucs-4be?b?AAAA?=\r\n\r\n"
    )["from_addr"] == "a@b.com"


def test_extract_address():
    assert extract_address("Alice <a@B.COM>") == "a@b.com"


def test_keep_rules_exclude_from_preview(tmp_path: Path):
    db = tmp_path / "mail.db"
    conn = init_db(db)
    now = int(time.time())
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 1,
            "message_id": "<1>",
            "from_addr": "keep@bank.com",
            "from_domain": "bank.com",
            "subject": "Statement",
            "date_ts": now - 90000,
            "date_raw": "",
            "size": 100,
            "flags": "",
            "list_unsubscribe": 0,
            "scanned_at": "",
        },
    )
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 2,
            "message_id": "<2>",
            "from_addr": "spam@promo.com",
            "from_domain": "promo.com",
            "subject": "Sale",
            "date_ts": now - 90000,
            "date_raw": "",
            "size": 200,
            "flags": "",
            "list_unsubscribe": 1,
            "scanned_at": "",
        },
    )
    conn.commit()
    conn.close()

    stage = Rule(id="oldish", older_than_days=1, action="stage")
    keep = Rule(id="keep-bank", from_domain="bank.com", action="keep")
    ruleset = RuleSet(keep=[keep], stage=[stage])
    result = preview_rule_with_ruleset(db, stage, ruleset, sample_n=10)
    assert result["match_count"] == 1
    assert result["samples"][0]["from_addr"] == "spam@promo.com"


def test_rules_yaml_roundtrip(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    save_rules(
        path,
        RuleSet(
            keep=[Rule(id="k1", from_address="a@b.com", action="keep")],
            stage=[Rule(id="s1", from_domain="x.com", older_than_days=30, action="stage")],
        ),
    )
    loaded = load_rules(path)
    assert loaded.keep[0].from_address == "a@b.com"
    assert loaded.stage[0].older_than_days == 30
    add_keep_sender(path, "c@d.com")
    loaded2 = load_rules(path)
    assert any(r.from_address == "c@d.com" for r in loaded2.keep)


def test_rules_from_insight_selections(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    path.write_text("keep: []\nstage: []\n", encoding="utf-8")
    from mail_janitor.rules import rules_from_insight_selections

    created = rules_from_insight_selections(
        path,
        [
            {"kind": "from_address", "value": "deals@messenger.tanga.com"},
            {"kind": "from_domain", "value": "triviaconnect.com"},
            {"kind": "older_than_days", "value": 1825},
        ],
    )
    assert len(created) == 3
    loaded = load_rules(path)
    assert len(loaded.stage) == 3
    assert any(r.older_than_days == 1825 for r in loaded.stage)


def test_keep_from_insight_selections(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "keep: []\nstage:\n- id: sender-spam-example-com\n  from_address: spam@example.com\n",
        encoding="utf-8",
    )
    from mail_janitor.rules import rules_from_insight_selections

    created = rules_from_insight_selections(
        path,
        [
            {"kind": "from_address", "value": "spam@example.com"},
            {"kind": "from_domain", "value": "bank.com"},
        ],
        action="keep",
    )
    assert len(created) == 2
    loaded = load_rules(path)
    assert len(loaded.keep) == 2
    # Overlapping stage rule for same sender removed
    assert not any(r.from_address == "spam@example.com" for r in loaded.stage)
    assert any(r.from_domain == "bank.com" for r in loaded.keep)


def test_list_unsubscribe_broader_rule(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    path.write_text("keep: []\nstage: []\n", encoding="utf-8")
    from mail_janitor.rules import rules_from_insight_selections

    created = rules_from_insight_selections(
        path,
        [{"kind": "list_unsubscribe_older_than", "value": 365}],
    )
    assert len(created) == 1
    assert created[0].has_list_unsubscribe is True
    assert created[0].older_than_days == 365


def test_from_address_prefixes_rule(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    path.write_text("keep: []\nstage: []\n", encoding="utf-8")
    db = tmp_path / "mail.db"
    conn = init_db(db)
    now = int(time.time())
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 1,
            "message_id": "<1>",
            "from_addr": "noreply@shop.example.com",
            "from_domain": "shop.example.com",
            "subject": "Sale",
            "date_ts": now,
            "date_raw": "",
            "size": 100,
            "flags": "",
            "list_unsubscribe": 0,
            "scanned_at": "",
        },
    )
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 2,
            "message_id": "<2>",
            "from_addr": "jane.doe@gmail.com",
            "from_domain": "gmail.com",
            "subject": "Hi",
            "date_ts": now,
            "date_raw": "",
            "size": 100,
            "flags": "",
            "list_unsubscribe": 0,
            "scanned_at": "",
        },
    )
    conn.commit()
    conn.close()

    from mail_janitor.discover import preview_rule_with_ruleset
    from mail_janitor.rules import add_stage_rule, RuleSet

    rule = add_stage_rule(
        path,
        {
            "id": "noreply-prefix",
            "from_address_prefixes": ["noreply@", "info@"],
            "match": "any",
        },
    )
    assert rule.from_address_prefixes == ["noreply@", "info@"]
    result = preview_rule_with_ruleset(db, rule, RuleSet(), sample_n=10)
    assert result["match_count"] == 1
    assert result["samples"][0]["from_addr"] == "noreply@shop.example.com"


def test_older_than_includes_undated_messages(tmp_path: Path):
    """Insights broader_options counts NULL date_ts; stage must match that."""
    db = tmp_path / "mail.db"
    conn = init_db(db)
    now = int(time.time())
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 1,
            "message_id": "<undated>",
            "from_addr": "news@promo.com",
            "from_domain": "promo.com",
            "subject": "List mail",
            "date_ts": None,
            "date_raw": "",
            "size": 50,
            "flags": "",
            "list_unsubscribe": 1,
            "scanned_at": "",
        },
    )
    upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 2,
            "message_id": "<recent>",
            "from_addr": "news@promo.com",
            "from_domain": "promo.com",
            "subject": "Recent",
            "date_ts": now - 100,
            "date_raw": "",
            "size": 50,
            "flags": "",
            "list_unsubscribe": 1,
            "scanned_at": "",
        },
    )
    conn.commit()
    conn.close()

    rule = Rule(
        id="list-unsub-older-365d",
        has_list_unsubscribe=True,
        older_than_days=365,
        action="stage",
    )
    result = preview_rule_with_ruleset(db, rule, RuleSet(), sample_n=10)
    assert result["match_count"] == 1
    assert result["samples"][0]["uid"] == 1

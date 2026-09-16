"""Firewall policy evaluation tests (no live IMAP)."""

from pathlib import Path

from mail_janitor.firewall_policy import (
    FirewallConfig,
    Rule,
    add_allow_sender,
    add_block_domain,
    evaluate_message,
    load_firewall,
)


def test_allow_beats_block():
    cfg = FirewallConfig(
        allow=[Rule(id="a", from_address="friend@x.com", action="keep")],
        block=[Rule(id="b", from_domain="x.com", action="stage")],
        heuristic_quarantine=True,
    )
    d = evaluate_message(
        {
            "from_addr": "friend@x.com",
            "from_domain": "x.com",
            "subject": "hi",
            "list_unsubscribe": 1,
        },
        cfg,
    )
    assert d.action == "pass"
    assert d.reason.startswith("allow:")


def test_block_quarantines():
    cfg = FirewallConfig(
        block=[Rule(id="b", from_domain="spam.test", action="stage")],
    )
    d = evaluate_message(
        {"from_addr": "a@spam.test", "from_domain": "spam.test", "subject": "x"},
        cfg,
    )
    assert d.action == "quarantine"
    assert "block:" in d.reason


def test_heuristic_off_by_default():
    cfg = FirewallConfig(heuristic_quarantine=False)
    d = evaluate_message(
        {
            "from_addr": "n@news.promo.com",
            "from_domain": "news.promo.com",
            "list_unsubscribe": 1,
            "subject": "sale",
        },
        cfg,
    )
    assert d.action == "pass"


def test_heuristic_on():
    cfg = FirewallConfig(heuristic_quarantine=True)
    d = evaluate_message(
        {
            "from_addr": "n@news.promo.com",
            "from_domain": "news.promo.com",
            "list_unsubscribe": 1,
            "subject": "sale",
        },
        cfg,
    )
    assert d.action == "quarantine"
    assert "list-unsub" in d.flags or "marketing-ish" in d.flags


def test_allow_block_persist(tmp_path: Path):
    path = tmp_path / "firewall.yaml"
    path.write_text("enabled: true\nallow: []\nblock: []\n", encoding="utf-8")
    add_block_domain(path, "bad.example")
    add_allow_sender(path, "good@bad.example")
    cfg = load_firewall(path)
    assert any(r.from_domain == "bad.example" for r in cfg.block)
    assert any(r.from_address == "good@bad.example" for r in cfg.allow)
    # allow should still win at evaluate time
    d = evaluate_message(
        {
            "from_addr": "good@bad.example",
            "from_domain": "bad.example",
            "subject": "hi",
        },
        cfg,
    )
    assert d.action == "pass"

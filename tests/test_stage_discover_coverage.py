from __future__ import annotations

import time
from pathlib import Path

import pytest

from mail_janitor.config import Profile
from mail_janitor.db import init_db, upsert_message


@pytest.fixture
def profile(tmp_path: Path):
    p = Profile(
        name="p",
        path=tmp_path,
        provider="imap",
        email="self@example.com",
        imap_host="h",
        imap_port=993,
        imap_ssl=True,
        app_password="pw",
        preview_sample_n=2,
    )
    p.rules_path.write_text(
        """
keep:
  - id: keep
    from_address: friend@example.com
stage:
  - id: addr
    from_address: junk@bad.test
  - id: domain
    from_domain: bad.test
    active: false
""",
        encoding="utf-8",
    )
    c = init_db(p.db_path)
    now = int(time.time())
    rows = [
        ("Inbox", 1, "junk@bad.test", "bad.test", "SALE unsubscribe", now - 9999999, 200000, 1),
        ("Inbox", 2, "friend@example.com", "example.com", "hello", now, 100, 0),
        ("Archive", 3, "other@bad.test", "bad.test", "newsletter", None, 300, 1),
        ("Inbox", 4, "self@example.com", "example.com", "me", now, 10, 0),
    ]
    for folder, uid, addr, domain, subject, ts, size, lu in rows:
        upsert_message(
            c,
            {
                "folder": folder,
                "uid": uid,
                "from_addr": addr,
                "from_domain": domain,
                "subject": subject,
                "date_ts": ts,
                "size": size,
                "list_unsubscribe": lu,
                "has_attachment": 1 if uid == 1 else None,
            },
        )
    c.commit()
    c.close()
    return p


def test_stage_rules_crud_and_listing(profile):
    from mail_janitor import stage

    events = []
    out = stage.stage_rules(
        profile, ["addr", "domain"], clear=True, progress_cb=lambda **k: events.append(k)
    )
    assert set(out["rules_applied"]) == {"addr", "domain"} and events
    with pytest.raises(ValueError):
        stage.stage_rules(profile, ["missing"])
    rows, total = stage.list_staged(profile)
    assert total >= 1 and rows
    rows, total = stage.list_staged(
        profile,
        included_only=False,
        from_domain="bad.test",
        rule_id=rows[0]["rule_id"],
        q="sale",
    )
    assert total >= 1
    row = rows[0]
    stage.set_staged_included(profile, row["folder"], row["uid"], False)
    assert stage.set_many_included(profile, [(row["folder"], row["uid"])], True) == 1
    assert (
        stage.set_all_staged_included(
            profile,
            False,
            from_domain="bad.test",
            rule_id=row["rule_id"],
            q="sale",
        )
        >= 1
    )
    stage.clear_staged(profile)
    assert stage.list_staged(profile, included_only=False)[1] == 0


def test_stage_by_confidence(profile):
    from mail_janitor import stage

    out = stage.stage_by_confidence(profile, confidence="junk", limit=1, clear=True)
    assert out["scanned"] and out["matched"] <= 1
    stage.stage_by_confidence(profile, confidence="keep", clear=True)
    stage.stage_by_confidence(profile, confidence="uncertain", clear=True)
    with pytest.raises(ValueError):
        stage.stage_by_confidence(profile, confidence="bad")
    profile.stage_inbox_only = False
    stage.stage_by_confidence(profile, confidence="junk")


def test_discover_and_previews(profile):
    from mail_janitor import discover
    from mail_janitor.rules import Rule, RuleSet

    data = discover.discover(profile, top_n=999, sender_offset=-1, domain_offset=-1)
    assert data["total_messages"] == 4
    assert data["age_buckets"] and data["broader_options"] and data["triage"]
    selections = discover.propose_cleanup_selections(
        profile,
        min_count=1,
        limit=10,
        kinds=["from_address", "from_domain"],
        heuristic_only=False,
        skip_existing_stage_rules=False,
    )
    assert selections
    discover.propose_cleanup_selections(
        profile,
        min_count=100,
        limit=1,
        kinds=["from_address", "from_domain"],
        heuristic_only=True,
    )

    ruleset = __import__("mail_janitor.rules", fromlist=["load_rules"]).load_rules(
        profile.rules_path
    )
    rule = ruleset.stage[0]
    one = discover.preview_rule(profile, rule)
    assert one["samples"] and one["criteria"]
    discover.preview_rule(profile, rule, apply_keep_exclusion=False)
    assert discover._preview_folder_scope(None, rule) == ("", [])
    no_samples = discover.preview_rule_with_ruleset(
        profile.db_path,
        rule,
        RuleSet(),
        0,
        include_samples=False,
        profile=None,
    )
    assert no_samples["samples"] == []
    assert discover.preview_all_stage_rules(profile)
    assert discover.preview_all_stage_rules(
        profile, ["domain", "addr"], include_samples=False, active_only=False
    )[0]["rule_id"] == "domain"


def test_build_triage_aggregation(profile, monkeypatch):
    from mail_janitor import discover

    c = init_db(profile.db_path)
    scores = iter(
        [
            {"confidence": "uncertain", "score": 2, "flags": ["a"]},
            {"confidence": "keep", "score": -2, "flags": ["b"]},
            {"confidence": "junk", "score": 5, "flags": ["c"]},
            {"confidence": "uncertain", "score": 1, "flags": ["d"]},
        ]
    )
    monkeypatch.setattr(discover, "score_message", lambda m: next(scores))
    out = discover.build_triage(c, "1=1", [], self_email="self@example.com")
    assert sum(out["counts"].values()) == 4
    c.close()


def test_discover_duplicate_senders_and_selection_filters(profile, monkeypatch):
    from mail_janitor import discover
    from mail_janitor.db import init_db, upsert_message

    c = init_db(profile.db_path)
    upsert_message(
        c,
        {
            "folder": "Inbox",
            "uid": 9,
            "from_addr": "friend@example.com",
            "from_domain": "example.com",
            "subject": "second",
            "size": 2,
        },
    )
    upsert_message(
        c,
        {
            "folder": "Inbox",
            "uid": 10,
            "from_addr": "friend@example.com",
            "from_domain": "example.com",
            "subject": "third",
            "size": 2,
        },
    )
    c.commit()
    scores = iter(
        [
            {"confidence": "uncertain", "score": 2, "flags": ["a"]},
            {"confidence": "keep", "score": -2, "flags": ["b"]},
            {"confidence": "junk", "score": 5, "flags": ["c"]},
            {"confidence": "uncertain", "score": 1, "flags": ["d"]},
            {"confidence": "keep", "score": 0, "flags": ["e"]},
            {"confidence": "keep", "score": -3, "flags": ["f"]},
        ]
    )
    monkeypatch.setattr(discover, "score_message", lambda m: next(scores))
    out = discover.build_triage(c, "1=1", [], self_email="")
    assert any(x["cnt"] >= 2 for x in out["likely_keep"])
    c.close()

    fake = {
        "existing_stage_addresses": ["existing@x"],
        "existing_stage_domains": ["existing.x"],
        "top_senders": [
            {"from_addr": "", "cnt": 100},
            {"from_addr": "self@example.com", "cnt": 100},
            {"from_addr": "low@x", "cnt": 1},
            {"from_addr": "existing@x", "cnt": 100},
            {"from_addr": "notlikely@x", "cnt": 100, "heuristic_likely": False},
            {"from_addr": "yes@x", "cnt": 100, "heuristic_likely": True},
        ],
        "top_domains": [
            {"from_domain": "", "cnt": 100},
            {"from_domain": "example.com", "cnt": 100},
            {"from_domain": "low.x", "cnt": 1},
            {"from_domain": "existing.x", "cnt": 100},
            {"from_domain": "not.x", "cnt": 100, "heuristic_likely": False},
            {"from_domain": "yes.x", "cnt": 100, "heuristic_likely": True},
        ],
    }
    monkeypatch.setattr(discover, "discover", lambda *a, **k: fake)
    got = discover.propose_cleanup_selections(
        profile, min_count=20, heuristic_only=True
    )
    assert {x["value"] for x in got} == {"yes@x", "yes.x"}
    assert len(
        discover.propose_cleanup_selections(
            profile,
            min_count=1,
            limit=1,
            kinds=["from_address"],
            skip_existing_stage_rules=False,
        )
    ) == 1
    assert len(
        discover.propose_cleanup_selections(
            profile,
            min_count=1,
            limit=1,
            kinds=["from_domain"],
            skip_existing_stage_rules=False,
        )
    ) == 1

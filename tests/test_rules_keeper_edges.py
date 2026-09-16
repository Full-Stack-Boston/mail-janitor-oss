from __future__ import annotations

from types import SimpleNamespace

import pytest

from mail_janitor.rules import Rule, RuleSet


def test_rule_construction_sql_and_serialization(tmp_path):
    import mail_janitor.rules as r

    with pytest.raises(ValueError):
        Rule.from_dict({}, "stage")
    assert r._normalize_suffix_or_none(None) is None
    assert r._normalize_suffix_or_none("") is None
    assert r._normalize_suffix_or_none("EXAMPLE.COM") == ".example.com"
    with pytest.raises(ValueError):
        r._normalize_addr_prefix("")
    assert r._normalize_addr_prefix("Name@example.com") == "name@"
    assert r._normalize_addr_prefix("name") == "name@"
    assert r._prefixes_from_dict(
        {"from_address_prefix": "a", "from_address_prefixes": ["a", "b"]}
    ) == ["a@", "b@"]
    assert r._int_or_none("") is None and r._int_or_none("2") == 2
    assert r._bool_or_none("") is None and r._bool_or_none(1) is True
    assert r.load_rules(tmp_path / "none") == RuleSet()

    rule = Rule(
        id="all",
        label="All",
        from_domain="x",
        from_domain_suffix=".x",
        from_address="a@x",
        from_address_prefixes=["no@"],
        subject_contains="Hi",
        older_than_days=1,
        folder="Inbox",
        has_list_unsubscribe=False,
        min_size=2,
        match="any",
        active=False,
    )
    sql, params = r.rule_sql_clauses(rule, 100000)
    assert " OR " in sql and len(params) == 9
    assert r.rule_sql_clauses(Rule(id="empty"), 0) == ("0", [])
    path = tmp_path / "rules.yaml"
    r.save_rules(path, RuleSet(keep=[rule], stage=[rule]))
    loaded = r.load_rules(path)
    assert not loaded.stage[0].active and loaded.get_stage_rule("none") is None
    assert r.active_stage_rules(loaded) == []


def test_keep_exclusion_and_rule_crud(tmp_path):
    import mail_janitor.rules as r

    rs = RuleSet(
        keep=[
            Rule(id="a", from_address="a@x"),
            Rule(id="d", from_domain="x"),
            Rule(id="s", from_domain_suffix=".x"),
            Rule(id="c", subject_contains="hi"),
            Rule(id="e"),
        ]
    )
    sql, params = r.keep_exclusion_sql(rs, 0)
    assert sql.startswith("NOT") and params
    assert r.keep_exclusion_sql(RuleSet(keep=[Rule(id="e")]), 0) == ("1", [])
    assert r.keep_exclusion_sql(RuleSet(), 0) == ("1", [])
    assert r._same_primary_criteria(Rule("a", from_address="x"), Rule("b", from_address="x"))
    assert r._same_primary_criteria(Rule("a", from_domain="x"), Rule("b", from_domain="x"))
    assert r._same_primary_criteria(
        Rule("a", from_domain_suffix=".x"), Rule("b", from_domain_suffix=".x")
    )
    assert r._same_primary_criteria(Rule("a", folder="X"), Rule("b", folder="X"))
    assert not r._same_primary_criteria(Rule("a"), Rule("b"))

    path = tmp_path / "rules.yaml"
    r.save_rules(path, RuleSet(stage=[Rule("s", from_address="a@x")]))
    keep = r.add_keep_sender(path, "A@X")
    assert keep.from_address == "a@x"
    assert not r.load_rules(path).stage
    assert r.add_keep_domain_suffix(path, "example.com").from_domain_suffix == ".example.com"
    with pytest.raises(ValueError):
        r.add_keep_domain_suffix(path, "")
    assert r.delete_keep_rule(path, "missing") is False
    assert r.delete_keep_rule(path, keep.id)
    assert r.backup_rules(path).exists()
    with pytest.raises(FileNotFoundError):
        r.backup_rules(tmp_path / "missing")
    r.add_keep_sender(path, "x@y")
    assert r.clear_all_keep_rules(path)["removed"] == 2
    assert r.clear_all_keep_rules(path, backup=False)["removed"] == 0

    rule = r.add_stage_rule(path, {"id": "x", "older_than_days": 2})
    assert r.update_stage_rule(path, "x", {"older_than_days": None}).older_than_days is None
    with pytest.raises(ValueError):
        r.update_stage_rule(path, "missing", {})
    assert not r.delete_stage_rule(path, "missing")
    assert r.delete_stage_rule(path, "x")
    r.add_stage_rule(path, {"id": "x", "from_domain": "none"})
    assert r.clear_all_stage_rules(path)["removed"] == 1
    assert r._slug("---") == "rule-item"


def test_rule_selection_conversion_and_batch(tmp_path):
    import mail_janitor.rules as r

    path = tmp_path / "rules.yaml"
    r.save_rules(path, RuleSet())
    values = [
        ("from_address", "A@X", "stage"),
        ("from_domain", "X.COM", "keep"),
        ("from_domain_suffix", "x.com", "keep"),
        ("subject_contains", "Hello", "stage"),
        ("folder", "Archive", "keep"),
        ("older_than_days", 3, "stage"),
        ("list_unsubscribe_older_than", 3, "stage"),
    ]
    for kind, value, action in values:
        assert r._selection_to_rule_data(kind, value, action=action)["id"]
    with pytest.raises(ValueError):
        r._selection_to_rule_data("from_domain_suffix", "", action="stage")
    with pytest.raises(ValueError):
        r._selection_to_rule_data("subject_contains", "", action="stage")
    with pytest.raises(ValueError):
        r._selection_to_rule_data("older_than_days", 1, action="keep")
    with pytest.raises(ValueError):
        r._selection_to_rule_data("list_unsubscribe_older_than", 1, action="keep")
    with pytest.raises(ValueError):
        r._selection_to_rule_data("bad", 1, action="stage")
    with pytest.raises(ValueError):
        r.rules_from_insight_selections(path, [], action="bad")
    events = []
    created = r.rules_from_insight_selections(
        path,
        [
            {"kind": "from_address", "value": "a@x"},
            {"kind": "from_address", "value": ""},
            {"kind": "folder", "value": "Inbox"},
        ],
        progress_cb=lambda **k: events.append(k),
    )
    assert len(created) == 2 and events[-1]["phase"] == "done"
    assert r.rules_from_insight_selections(
        path, [{"kind": "from_address", "value": "a@x"}], action="keep"
    )


def test_rules_business_and_archive(tmp_path):
    import mail_janitor.rules as r
    from mail_janitor.config import Profile
    from mail_janitor.db import init_db, upsert_message

    p = Profile("p", tmp_path, "imap", "e", "h", 1, True)
    r.save_rules(
        p.rules_path,
        RuleSet(
            stage=[
                Rule("hit", from_address="noreply@x"),
                Rule("miss", from_domain="z"),
                Rule("inactive", from_domain="x", active=False),
            ]
        ),
    )
    c = init_db(p.db_path)
    upsert_message(
        c,
        {
            "folder": "Inbox",
            "uid": 1,
            "from_addr": "noreply@x",
            "from_domain": "x",
            "size": 3,
        },
    )
    c.commit()
    c.close()
    assert r.preview_business_prefix_matches(p.rules_path, p.db_path)["match_count"] == 1
    assert r.add_stage_business_prefix_rule(p.rules_path).from_address_prefixes
    with pytest.raises(TypeError):
        r.archive_dormant_stage_rules(SimpleNamespace())
    out = r.archive_dormant_stage_rules(p, sample_limit=1)
    assert out["archived"] >= 0


def test_keeper_full_workflows(tmp_path, monkeypatch):
    import mail_janitor.keeper as k
    import mail_janitor.rules as r
    from mail_janitor.config import Profile
    from mail_janitor.db import init_db, upsert_message

    p = Profile("p", tmp_path, "imap", "e", "h", 1, True)
    r.save_rules(
        p.rules_path,
        RuleSet(
            keep=[
                Rule("dom", from_domain="gmail.com"),
                Rule("addr", from_address="only@x"),
                Rule("empty"),
            ]
        ),
    )
    c = init_db(p.db_path)
    for uid, addr, domain in [
        (1, "a@gmail.com", "gmail.com"),
        (2, "b@gmail.com", "gmail.com"),
        (3, "only@x", "x"),
    ]:
        upsert_message(
            c,
            {
                "folder": "Inbox",
                "uid": uid,
                "from_addr": addr,
                "from_domain": domain,
                "subject": "hello",
                "date_ts": 1,
                "size": 10,
            },
        )
    c.commit()
    c.close()

    assert k.normalize_domain_suffix("X.COM") == ".x.com"
    with pytest.raises(ValueError):
        k.normalize_domain_suffix("")
    assert k.keep_inclusion_sql(RuleSet(), 0) == ("0", [])
    assert k.keep_inclusion_sql(RuleSet(keep=[Rule("e")]), 0) == ("0", [])
    assert k.audit_keep_rules(p)
    assert k.list_keep_rule_senders(p, "dom")["total_senders"] == 2
    with pytest.raises(ValueError):
        k.list_keep_rule_senders(p, "missing")
    with pytest.raises(ValueError):
        k.list_keep_rule_senders(p, "addr")

    # Narrow by explicit keep and by exclusion.
    out = k.narrow_broad_keep_rule(p, "dom", keep_addresses=["a@gmail.com"])
    assert out["created_keep_rules"] == 1
    k.restore_broad_domain_keep(p, "gmail.com")
    out = k.narrow_broad_keep_rule(p, "keep-gmail-com", exclude_addresses=["b@gmail.com"])
    assert out["excluded_senders"] == 1
    with pytest.raises(ValueError):
        k.narrow_broad_keep_rule(p, out["created"][0])
    k.restore_broad_domain_keep(p, "gmail.com", remove_address_keeps=False)
    with pytest.raises(ValueError):
        k.restore_broad_domain_keep(p, "bad@x")

    assert k.mark_seen(p, []) == 0
    assert k.mark_seen(p, [("Inbox", 1)]) == 1
    assert k.coverage_stats(p)["total_indexed"] == 3
    search = k.search_indexed(
        p,
        domain_suffix="gmail.com",
        from_contains="a",
        domain_contains="gmail",
        subject_contains="hell",
        unseen_only=True,
        folder="Inbox",
        not_kept_only=False,
    )
    assert search["senders"] >= 0
    assert k.preview_domain_suffix(p, "gmail.com")["suffix"] == ".gmail.com"
    c = init_db(p.db_path)
    c.execute("INSERT INTO staged(folder,uid,rule_id) VALUES('Inbox',1,'x')")
    c.commit()
    c.close()
    assert k.reset_review_state(p)["staged_cleared"] == 1
    assert k.reset_review_state(p, staged=False, evaluated=False) == {}

    class Client:
        def __init__(self, data):
            self.imap = SimpleNamespace(uid=lambda *a: data)

        def select(self, *a, **k):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        k,
        "get_provider",
        lambda n: SimpleNamespace(connect=lambda p: Client(("OK", ["1 2"]))),
    )
    assert k.search_imap_body(p, 'he"llo')["imap_matches"] == 2
    monkeypatch.setattr(
        k,
        "get_provider",
        lambda n: SimpleNamespace(connect=lambda p: Client(("NO", []))),
    )
    assert k.search_imap_body(p, "hello")["total"] == 0
    with pytest.raises(ValueError):
        k.search_imap_body(p, "x")


def test_keeper_remaining_defensive_paths(tmp_path, monkeypatch):
    import mail_janitor.keeper as k
    import mail_janitor.rules as r
    from mail_janitor.config import Profile
    from mail_janitor.db import init_db

    p = Profile("p", tmp_path, "imap", "e", "h", 1, True)
    r.save_rules(
        p.rules_path,
        RuleSet(
            keep=[
                Rule("zero", from_domain="none"),
                Rule("suffix", from_domain_suffix=".com"),
            ]
        ),
    )
    init_db(p.db_path).close()
    assert k.audit_keep_rules(p) == []
    with pytest.raises(ValueError, match="required"):
        k.narrow_broad_keep_rule(p, "suffix")
    monkeypatch.setattr(k, "delete_keep_rule", lambda *a: False)
    with pytest.raises(ValueError, match="not found"):
        k.narrow_broad_keep_rule(p, "suffix", keep_addresses=[])

    # Defensive zero-clause checks are reachable with a corrupt/custom rule compiler.
    monkeypatch.setattr(k, "rule_sql_clauses", lambda *a: ("0", []))
    with pytest.raises(ValueError, match="criteria"):
        k.list_keep_rule_senders(p, "suffix")
    with pytest.raises(ValueError, match="criteria"):
        k.narrow_broad_keep_rule(p, "suffix", keep_addresses=[])


def test_keeper_high_volume_broad_rules(tmp_path):
    import mail_janitor.keeper as k
    import mail_janitor.rules as r
    from mail_janitor.config import Profile
    from mail_janitor.db import init_db, upsert_message

    p = Profile("p", tmp_path, "imap", "e", "h", 1, True)
    r.save_rules(
        p.rules_path,
        RuleSet(
            keep=[
                Rule("domain", from_domain="custom.test"),
                Rule("suffix", from_domain_suffix=".example"),
            ]
        ),
    )
    c = init_db(p.db_path)
    for uid in range(1, 201):
        upsert_message(
            c,
            {
                "folder": "Inbox",
                "uid": uid,
                "from_addr": f"a{uid}@custom.test",
                "from_domain": "custom.test",
            },
        )
        upsert_message(
            c,
            {
                "folder": "Other",
                "uid": uid,
                "from_addr": f"a{uid}@sub.example",
                "from_domain": "sub.example",
            },
        )
    c.commit()
    c.close()
    audit = {x["rule_id"]: x for x in k.audit_keep_rules(p)}
    assert audit["domain"]["broad"] and audit["suffix"]["broad"]

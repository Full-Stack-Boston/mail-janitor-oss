"""Keep explorer and domain-suffix rules."""

from pathlib import Path

from mail_janitor.db import init_db, upsert_message
from mail_janitor.keeper import (
    audit_keep_rules,
    coverage_stats,
    list_keep_rule_senders,
    narrow_broad_keep_rule,
    preview_domain_suffix,
    restore_broad_domain_keep,
    search_indexed,
)
from mail_janitor.config import Profile
from mail_janitor.rules import (
    add_keep_domain_suffix,
    keep_exclusion_sql,
    load_rules,
    rule_sql_clauses,
)
import time


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
        app_password="x",
    )


def _seed(conn, **kw):
    upsert_message(
        conn,
        {
            "folder": "Inbox",
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


def test_domain_suffix_keep_rule(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="a@salemstate.edu", from_domain="salemstate.edu")
    _seed(conn, uid=2, from_addr="b@spam.com", from_domain="spam.com")
    conn.commit()
    conn.close()

    add_keep_domain_suffix(p.rules_path, ".edu")
    rs = load_rules(p.rules_path)
    now = int(time.time())
    clause, params = rule_sql_clauses(rs.keep[0], now)
    assert "LIKE" in clause
    conn = init_db(p.db_path)
    kept = conn.execute(
        f"SELECT COUNT(*) FROM messages WHERE {clause}", params
    ).fetchone()[0]
    assert kept == 1
    keep_sql, keep_params = keep_exclusion_sql(rs, now)
    eligible = conn.execute(
        f"SELECT COUNT(*) FROM messages WHERE {keep_sql}", keep_params
    ).fetchone()[0]
    assert eligible == 1
    conn.close()


def test_search_and_stats(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="x@bonaloop.com", from_domain="bonaloop.com", subject="scout trip")
    _seed(conn, uid=2, from_addr="y@gmail.com", from_domain="gmail.com", subject="Re: hello")
    conn.commit()
    conn.close()

    r = search_indexed(p, domain_contains="bonaloop", not_kept_only=True)
    assert r["total"] == 1
    assert r["rows"][0]["from_domain"] == "bonaloop.com"

    stats = coverage_stats(p)
    assert stats["total_indexed"] == 2
    assert stats["not_kept"] == 2

    prev = preview_domain_suffix(p, ".com")
    assert prev["not_kept_matches"] >= 1


def test_audit_keep_rules_lists_matches(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="shop@amazon.com", from_domain="amazon.com")
    _seed(conn, uid=2, from_addr="b@spam.com", from_domain="spam.com")
    conn.commit()
    conn.close()

    from mail_janitor.rules import add_keep_rule

    add_keep_rule(
        p.rules_path,
        {"id": "keep-amazon-com", "label": "amazon", "from_domain": "amazon.com"},
    )
    audit = audit_keep_rules(p, sample_n=1)
    assert len(audit) == 1
    assert audit[0]["rule_id"] == "keep-amazon-com"
    assert audit[0]["match_count"] == 1
    stats = coverage_stats(p)
    assert stats["kept"] == 1


def test_narrow_broad_keep_rule(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="friend@gmail.com", from_domain="gmail.com")
    _seed(conn, uid=2, from_addr="spam@gmail.com", from_domain="gmail.com")
    _seed(conn, uid=3, from_addr="other@spam.com", from_domain="spam.com")
    conn.commit()
    conn.close()

    from mail_janitor.rules import add_keep_rule

    add_keep_rule(
        p.rules_path,
        {"id": "keep-gmail-com", "label": "gmail", "from_domain": "gmail.com"},
    )
    senders = list_keep_rule_senders(p, "keep-gmail-com")
    assert senders["total_senders"] == 2

    result = narrow_broad_keep_rule(
        p,
        "keep-gmail-com",
        exclude_addresses=["spam@gmail.com"],
    )
    assert result["kept_senders"] == 1
    assert result["excluded_senders"] == 1

    stats = coverage_stats(p)
    assert stats["kept"] == 1
    assert stats["not_kept"] == 2


def test_restore_broad_domain_keep(tmp_path: Path):
    p = _profile(tmp_path)
    conn = init_db(p.db_path)
    _seed(conn, uid=1, from_addr="friend@gmail.com", from_domain="gmail.com")
    _seed(conn, uid=2, from_addr="spam@gmail.com", from_domain="gmail.com")
    conn.commit()
    conn.close()

    from mail_janitor.rules import add_keep_rule

    add_keep_rule(
        p.rules_path,
        {"id": "keep-gmail-com", "label": "gmail", "from_domain": "gmail.com"},
    )
    narrow_broad_keep_rule(p, "keep-gmail-com", exclude_addresses=["spam@gmail.com"])

    result = restore_broad_domain_keep(p, "gmail.com")
    assert result["restored_rule"] == "keep-gmail-com"
    assert result["removed_address_rules"] == 1

    stats = coverage_stats(p)
    assert stats["kept"] == 2

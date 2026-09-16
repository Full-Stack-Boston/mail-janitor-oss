"""Keep discovery: search indexed mail, coverage stats, bulk keep rules."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from mail_janitor.config import Profile
from mail_janitor.db import init_db
from mail_janitor.parse_headers import format_size, format_ts
from mail_janitor.providers import get_provider
from mail_janitor.providers.base import with_backoff
from mail_janitor.rules import (
    Rule,
    RuleSet,
    add_keep_rule,
    add_keep_sender,
    backup_rules,
    delete_keep_rule,
    keep_exclusion_sql,
    load_rules,
    rule_sql_clauses,
    save_rules,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain_suffix(value: str) -> str:
    s = (value or "").strip().lower()
    if not s:
        raise ValueError("domain suffix required")
    if not s.startswith("."):
        s = "." + s
    return s


def keep_inclusion_sql(ruleset: RuleSet, now_ts: int) -> tuple[str, list[Any]]:
    """SQL fragment true when a row matches any keep rule."""
    if not ruleset.keep:
        return "0", []
    parts: list[str] = []
    params: list[Any] = []
    for rule in ruleset.keep:
        clause, p = rule_sql_clauses(rule, now_ts)
        if clause == "0":
            continue
        parts.append(clause)
        params.extend(p)
    if not parts:
        return "0", []
    return f"({' OR '.join(parts)})", params


_BROAD_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "amazon.com",
}


def audit_keep_rules(profile: Profile, *, sample_n: int = 3) -> list[dict[str, Any]]:
    """Per keep-rule match counts + sample senders (overlaps possible across rules)."""
    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    ruleset = load_rules(profile.rules_path)
    rows: list[dict[str, Any]] = []
    for rule in ruleset.keep:
        clause, params = rule_sql_clauses(rule, now_ts)
        if clause == "0":
            continue
        agg = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt,
                   COALESCE(SUM(size),0) AS bytes,
                   COUNT(DISTINCT from_addr) AS senders
            FROM messages WHERE {clause}
            """,
            params,
        ).fetchone()
        cnt = int(agg["cnt"] or 0)
        if cnt == 0:
            continue
        crit = (
            rule.from_domain_suffix
            or rule.from_domain
            or rule.from_address
            or (", ".join(rule.from_address_prefixes) if rule.from_address_prefixes else None)
            or rule.subject_contains
            or rule.folder
        )
        broad = False
        if rule.from_domain and rule.from_domain in _BROAD_DOMAINS:
            broad = True
        elif rule.from_domain and cnt >= 200:
            broad = True
        elif rule.from_domain_suffix and cnt >= 200:
            broad = True
        narrowable = broad and bool(rule.from_domain or rule.from_domain_suffix)
        samples = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT from_addr, subject, folder, date_ts
                FROM messages WHERE {clause}
                ORDER BY date_ts IS NULL, date_ts DESC
                LIMIT ?
                """,
                params + [sample_n],
            ).fetchall()
        ]
        for s in samples:
            s["date_human"] = format_ts(s.get("date_ts"))
        rows.append(
            {
                "rule_id": rule.id,
                "label": rule.label,
                "criteria": crit,
                "match_count": cnt,
                "senders": int(agg["senders"] or 0),
                "bytes_human": format_size(agg["bytes"]),
                "broad": broad,
                "narrowable": narrowable,
                "from_domain": rule.from_domain,
                "from_domain_suffix": rule.from_domain_suffix,
                "samples": samples,
            }
        )
    conn.close()
    rows.sort(key=lambda x: (-x["match_count"], x["rule_id"]))
    return rows


def _get_keep_rule(ruleset: RuleSet, rule_id: str) -> Rule:
    for rule in ruleset.keep:
        if rule.id == rule_id:
            return rule
    raise ValueError(f"keep rule not found: {rule_id}")


def list_keep_rule_senders(
    profile: Profile,
    rule_id: str,
    *,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Distinct senders matching a domain/suffix keep rule, for narrowing."""
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    ruleset = load_rules(profile.rules_path)
    rule = _get_keep_rule(ruleset, rule_id)
    if not rule.from_domain and not rule.from_domain_suffix:
        conn.close()
        raise ValueError("only domain or suffix keep rules can be narrowed")

    clause, params = rule_sql_clauses(rule, now_ts)
    if clause == "0":
        conn.close()
        raise ValueError("keep rule has no match criteria")

    addr_keeps = {r.from_address for r in ruleset.keep if r.from_address}
    total_senders = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT from_addr) AS c FROM messages WHERE {clause}",
            params,
        ).fetchone()["c"]
    )
    rows = [
        dict(r)
        for r in conn.execute(
            f"""
            SELECT from_addr,
                   COUNT(*) AS message_count,
                   MAX(date_ts) AS latest_ts,
                   MAX(subject) AS sample_subject
            FROM messages
            WHERE {clause}
            GROUP BY from_addr
            ORDER BY message_count DESC, from_addr
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
    ]
    conn.close()
    for r in rows:
        r["latest_human"] = format_ts(r.get("latest_ts"))
        r["has_address_keep"] = r["from_addr"] in addr_keeps
    crit = rule.from_domain or rule.from_domain_suffix or rule_id
    return {
        "rule_id": rule_id,
        "criteria": crit,
        "total_senders": total_senders,
        "limit": limit,
        "offset": offset,
        "senders": rows,
    }


def narrow_broad_keep_rule(
    profile: Profile,
    rule_id: str,
    *,
    keep_addresses: list[str] | None = None,
    exclude_addresses: list[str] | None = None,
) -> dict[str, Any]:
    """Replace a broad domain/suffix keep rule with per-address keeps."""
    ruleset = load_rules(profile.rules_path)
    rule = _get_keep_rule(ruleset, rule_id)
    if not rule.from_domain and not rule.from_domain_suffix:
        raise ValueError("only domain or suffix keep rules can be narrowed")

    now_ts = int(time.time())
    clause, params = rule_sql_clauses(rule, now_ts)
    if clause == "0":
        raise ValueError("keep rule has no match criteria")

    conn = init_db(profile.db_path)
    all_addrs = [
        str(r["from_addr"])
        for r in conn.execute(
            f"SELECT DISTINCT from_addr FROM messages WHERE {clause} ORDER BY from_addr",
            params,
        ).fetchall()
    ]
    conn.close()

    if exclude_addresses is not None:
        excluded = {a.strip().lower() for a in exclude_addresses if a and a.strip()}
        keep_addrs = sorted(a for a in all_addrs if a.lower() not in excluded)
    elif keep_addresses is not None:
        keep_addrs = sorted({a.strip().lower() for a in keep_addresses if a and a.strip()})
    else:
        raise ValueError("keep_addresses or exclude_addresses required")

    rules_backup = str(backup_rules(profile.rules_path))

    if not delete_keep_rule(profile.rules_path, rule_id):
        raise ValueError(f"keep rule not found: {rule_id}")

    created: list[str] = []
    for addr in keep_addrs:
        added = add_keep_sender(profile.rules_path, addr)
        created.append(added.id)

    return {
        "removed_rule": rule_id,
        "criteria": rule.from_domain or rule.from_domain_suffix,
        "created_keep_rules": len(created),
        "created": created,
        "kept_senders": len(keep_addrs),
        "excluded_senders": len(all_addrs) - len(keep_addrs),
        "total_senders": len(all_addrs),
        "backup": rules_backup,
    }


def restore_broad_domain_keep(
    profile: Profile,
    domain: str,
    *,
    rule_id: str | None = None,
    remove_address_keeps: bool = True,
) -> dict[str, Any]:
    """Re-add a whole-domain keep rule after a partial/incorrect narrow."""
    dom = (domain or "").strip().lower()
    if not dom or "@" in dom:
        raise ValueError("domain required (e.g. gmail.com)")

    removed: list[str] = []
    if remove_address_keeps:
        ruleset = load_rules(profile.rules_path)
        suffix = f"@{dom}"
        keep_after: list[Rule] = []
        for rule in ruleset.keep:
            if rule.from_address and rule.from_address.endswith(suffix):
                removed.append(rule.id)
                continue
            keep_after.append(rule)
        if removed:
            ruleset.keep = keep_after
            save_rules(profile.rules_path, ruleset)

    rid = rule_id or f"keep-{dom.replace('.', '-')}"
    added = add_keep_rule(
        profile.rules_path,
        {
            "id": rid,
            "label": f"Keep domain {dom}",
            "from_domain": dom,
        },
    )
    return {
        "restored_rule": added.id,
        "domain": dom,
        "removed_address_rules": len(removed),
        "removed": removed,
    }


def reset_review_state(profile: Profile, *, staged: bool = True, evaluated: bool = True) -> dict[str, int]:
    """Clear staged queue and/or keeper_seen evaluated markers (not rules)."""
    conn = init_db(profile.db_path)
    out: dict[str, int] = {}
    try:
        if staged:
            cur = conn.execute("DELETE FROM staged")
            out["staged_cleared"] = int(cur.rowcount or 0)
        if evaluated:
            cur = conn.execute("DELETE FROM keeper_seen")
            out["evaluated_cleared"] = int(cur.rowcount or 0)
        conn.commit()
    finally:
        conn.close()
    return out


def coverage_stats(profile: Profile) -> dict[str, Any]:
    """Counts: total, kept, not kept (cleanup-eligible), evaluated, remain."""
    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    ruleset = load_rules(profile.rules_path)
    keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
    incl_sql, incl_params = keep_inclusion_sql(ruleset, now_ts)

    total = int(conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"])
    kept = 0
    if incl_sql != "0":
        kept = int(
            conn.execute(f"SELECT COUNT(*) AS c FROM messages WHERE {incl_sql}", incl_params).fetchone()["c"]
        )
    not_kept = int(
        conn.execute(f"SELECT COUNT(*) AS c FROM messages WHERE ({keep_sql})", keep_params).fetchone()["c"]
    )
    evaluated = int(conn.execute("SELECT COUNT(*) AS c FROM keeper_seen").fetchone()["c"])
    remain = int(
        conn.execute(
            f"""
            SELECT COUNT(*) AS c FROM messages m
            WHERE ({keep_sql})
              AND NOT EXISTS (
                SELECT 1 FROM keeper_seen s
                WHERE s.folder = m.folder AND s.uid = m.uid
              )
            """,
            keep_params,
        ).fetchone()["c"]
    )
    inbox = int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM messages WHERE lower(folder) = lower(?)",
            (profile.inbox_folder,),
        ).fetchone()["c"]
    )
    conn.close()
    stage_rule_count = len(ruleset.stage)
    return {
        "total_indexed": total,
        "inbox_indexed": inbox,
        "kept": kept,
        "not_kept": not_kept,
        "evaluated": evaluated,
        "remain_to_review": remain,
        "keep_rule_count": len(ruleset.keep),
        "stage_rule_count": stage_rule_count,
        "note": (
            "Kept = indexed messages matching any keep rule (overlaps across rules). "
            "Not kept = cleanup-eligible. Inbox remaining (header) is Inbox folder only."
        ),
    }


def mark_seen(profile: Profile, items: list[tuple[str, int]]) -> int:
    if not items:
        return 0
    conn = init_db(profile.db_path)
    try:
        conn.executemany(
            """
            INSERT INTO keeper_seen (folder, uid, seen_at)
            VALUES (?, ?, ?)
            ON CONFLICT(folder, uid) DO UPDATE SET seen_at = excluded.seen_at
            """,
            [(f, u, _now()) for f, u in items],
        )
        conn.commit()
        return len(items)
    finally:
        conn.close()


def search_indexed(
    profile: Profile,
    *,
    domain_suffix: str | None = None,
    from_contains: str | None = None,
    domain_contains: str | None = None,
    subject_contains: str | None = None,
    not_kept_only: bool = True,
    unseen_only: bool = False,
    folder: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    ruleset = load_rules(profile.rules_path)
    clauses = ["1=1"]
    params: list[Any] = []

    if not_kept_only:
        keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
        clauses.append(f"({keep_sql})")
        params.extend(keep_params)

    if unseen_only:
        clauses.append(
            "NOT EXISTS (SELECT 1 FROM keeper_seen s WHERE s.folder = messages.folder AND s.uid = messages.uid)"
        )

    if folder:
        clauses.append("folder = ?")
        params.append(folder)

    if domain_suffix:
        suf = normalize_domain_suffix(domain_suffix)
        clauses.append("from_domain LIKE ?")
        params.append(f"%{suf}")

    if from_contains:
        clauses.append("lower(from_addr) LIKE ?")
        params.append(f"%{from_contains.lower()}%")

    if domain_contains:
        clauses.append("lower(from_domain) LIKE ?")
        params.append(f"%{domain_contains.lower()}%")

    if subject_contains:
        clauses.append("lower(subject) LIKE ?")
        params.append(f"%{subject_contains.lower()}%")

    where = " AND ".join(clauses)
    total = int(conn.execute(f"SELECT COUNT(*) AS c FROM messages WHERE {where}", params).fetchone()["c"])

    rows = [
        dict(r)
        for r in conn.execute(
            f"""
            SELECT folder, uid, from_addr, from_domain, subject, date_ts, size,
                   list_unsubscribe,
                   EXISTS (
                     SELECT 1 FROM keeper_seen s
                     WHERE s.folder = messages.folder AND s.uid = messages.uid
                   ) AS evaluated
            FROM messages
            WHERE {where}
            ORDER BY date_ts IS NULL, date_ts DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
    ]
    for r in rows:
        r["date_human"] = format_ts(r.get("date_ts"))
        r["size_human"] = format_size(r.get("size"))
        r["evaluated"] = bool(r.get("evaluated"))

    # Aggregate hints for bulk keep
    agg = conn.execute(
        f"""
        SELECT COUNT(DISTINCT from_addr) AS senders,
               COUNT(DISTINCT from_domain) AS domains
        FROM messages WHERE {where}
        """,
        params,
    ).fetchone()
    conn.close()

    return {
        "total": total,
        "rows": rows,
        "senders": int(agg["senders"] or 0),
        "domains": int(agg["domains"] or 0),
        "limit": limit,
        "offset": offset,
    }


def preview_domain_suffix(profile: Profile, suffix: str) -> dict[str, Any]:
    suf = normalize_domain_suffix(suffix)
    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    ruleset = load_rules(profile.rules_path)
    keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
    row = conn.execute(
        f"""
        SELECT COUNT(*) AS cnt,
               COALESCE(SUM(size),0) AS bytes,
               COUNT(DISTINCT from_domain) AS domains,
               COUNT(DISTINCT from_addr) AS senders
        FROM messages
        WHERE from_domain LIKE ? AND ({keep_sql})
        """,
        [f"%{suf}"] + keep_params,
    ).fetchone()
    conn.close()
    return {
        "suffix": suf,
        "not_kept_matches": int(row["cnt"] or 0),
        "bytes": int(row["bytes"] or 0),
        "bytes_human": format_size(row["bytes"]),
        "domains": int(row["domains"] or 0),
        "senders": int(row["senders"] or 0),
    }


def search_imap_body(
    profile: Profile,
    keyword: str,
    *,
    folder: str = "Inbox",
    limit: int = 100,
) -> dict[str, Any]:
    """Slow IMAP TEXT search; returns indexed rows for matching UIDs."""
    keyword = (keyword or "").strip()
    if len(keyword) < 2:
        raise ValueError("body keyword must be at least 2 characters")

    client = get_provider(profile.provider).connect(profile)
    try:
        with_backoff(lambda: client.select(folder, readonly=True))
        # Yahoo supports TEXT search on many folders
        typ, data = with_backoff(
            lambda: client.imap.uid(
                "search", None, "TEXT", f'"{keyword.replace(chr(34), "")}"'
            )
        )
        uids: list[int] = []
        if typ == "OK" and data and data[0]:
            uids = [int(x) for x in data[0].split() if str(x).isdigit()]
        uids = uids[:limit]
    finally:
        client.close()

    if not uids:
        return {"keyword": keyword, "folder": folder, "total": 0, "rows": []}

    conn = init_db(profile.db_path)
    placeholders = ", ".join("?" for _ in uids)
    rows = [
        dict(r)
        for r in conn.execute(
            f"""
            SELECT folder, uid, from_addr, from_domain, subject, date_ts, size,
                   list_unsubscribe,
                   EXISTS (
                     SELECT 1 FROM keeper_seen s
                     WHERE s.folder = messages.folder AND s.uid = messages.uid
                   ) AS evaluated
            FROM messages
            WHERE folder = ? AND uid IN ({placeholders})
            ORDER BY date_ts IS NULL, date_ts DESC
            """,
            [folder] + uids,
        ).fetchall()
    ]
    conn.close()
    for r in rows:
        r["date_human"] = format_ts(r.get("date_ts"))
        r["size_human"] = format_size(r.get("size"))
        r["evaluated"] = bool(r.get("evaluated"))

    return {
        "keyword": keyword,
        "folder": folder,
        "imap_matches": len(uids),
        "indexed_matches": len(rows),
        "total": len(rows),
        "rows": rows,
    }

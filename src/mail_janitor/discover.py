"""Discovery aggregates and rule preview (metadata only)."""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from mail_janitor.config import Profile
from mail_janitor.db import init_db
from mail_janitor.heuristics import annotate_domain, annotate_sender, score_message
from mail_janitor.parse_headers import format_size, format_ts
from mail_janitor.rules import Rule, RuleSet, keep_exclusion_sql, load_rules, rule_sql_clauses


SAMPLE_COLS = (
    "folder",
    "uid",
    "from_addr",
    "from_domain",
    "subject",
    "date_ts",
    "size",
    "list_unsubscribe",
)

DEFAULT_TOP_N = 100


def build_triage(
    conn: sqlite3.Connection,
    keep_sql: str,
    keep_params: list[Any],
    *,
    self_email: str = "",
    keep_sample_n: int = 120,
) -> dict[str, Any]:
    """Score cleanup-eligible messages into junk / uncertain / keep piles."""
    self_email = (self_email or "").lower()
    rows = conn.execute(
        f"""
        SELECT folder, uid, from_addr, from_domain, subject, date_ts, size,
               list_unsubscribe
        FROM messages
        WHERE {keep_sql}
        """,
        keep_params,
    ).fetchall()

    piles = {"junk": 0, "uncertain": 0, "keep": 0}
    bytes_piles = {"junk": 0, "uncertain": 0, "keep": 0}
    by_addr: dict[str, dict[str, Any]] = {}

    for raw in rows:
        msg = dict(raw)
        sc = score_message(msg)
        conf = sc["confidence"]
        piles[conf] += 1
        bytes_piles[conf] += int(msg.get("size") or 0)

        addr = (msg.get("from_addr") or "").lower().strip()
        if not addr or addr == self_email:
            continue
        if conf == "junk":
            continue

        bucket = by_addr.get(addr)
        if bucket is None:
            by_addr[addr] = {
                "from_addr": addr,
                "from_domain": msg.get("from_domain") or "",
                "cnt": 1,
                "bytes": int(msg.get("size") or 0),
                "confidence": conf,
                "score": sc["score"],
                "flags": set(sc["flags"]),
                "sample_subject": msg.get("subject") or "",
            }
            continue
        bucket["cnt"] += 1
        bucket["bytes"] += int(msg.get("size") or 0)
        bucket["flags"].update(sc["flags"])
        # Prefer strongest keep lean (lowest score)
        if sc["score"] < bucket["score"]:
            bucket["score"] = sc["score"]
            bucket["confidence"] = conf
            bucket["sample_subject"] = msg.get("subject") or bucket["sample_subject"]
        elif conf == "keep":
            bucket["confidence"] = "keep"

    rank = {"keep": 0, "uncertain": 1}
    likely_keep: list[dict[str, Any]] = []
    for b in by_addr.values():
        likely_keep.append(
            {
                "from_addr": b["from_addr"],
                "from_domain": b["from_domain"],
                "cnt": b["cnt"],
                "bytes": b["bytes"],
                "bytes_human": format_size(b["bytes"]),
                "confidence": b["confidence"],
                "score": b["score"],
                "flags": sorted(b["flags"]),
                "sample_subject": b["sample_subject"],
                "kind": "from_address",
                "value": b["from_addr"],
            }
        )
    likely_keep.sort(
        key=lambda x: (rank.get(x["confidence"], 9), x["score"], -x["cnt"], x["from_addr"])
    )

    return {
        "counts": piles,
        "bytes": bytes_piles,
        "bytes_human": {k: format_size(v) for k, v in bytes_piles.items()},
        "likely_keep": likely_keep[:keep_sample_n],
        "likely_keep_total": len(likely_keep),
        "junk_count": piles["junk"],
        "uncertain_count": piles["uncertain"],
        "keep_count": piles["keep"],
    }


def discover(
    profile: Profile,
    top_n: int = DEFAULT_TOP_N,
    sender_offset: int = 0,
    domain_offset: int = 0,
) -> dict[str, Any]:
    """
    Insights aggregates.

    Keep-rule matches are excluded from cleanup-oriented lists (senders, domains,
    folders, age buckets, list-unsub, largest) so preserved mail stops resurfacing.
    Totals still reflect the full local index.
    """
    top_n = max(1, min(int(top_n), 500))
    sender_offset = max(0, int(sender_offset))
    domain_offset = max(0, int(domain_offset))

    conn = init_db(profile.db_path)
    try:
        now_ts = int(time.time())
        ruleset = load_rules(profile.rules_path)
        keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
        eligible = f"({keep_sql})"
        self_email = (profile.email or "").lower()

        total = conn.execute(
            "SELECT COUNT(*) AS c, COALESCE(SUM(size),0) AS s FROM messages"
        ).fetchone()
        eligible_total = conn.execute(
            f"SELECT COUNT(*) AS c, COALESCE(SUM(size),0) AS s FROM messages WHERE {eligible}",
            keep_params,
        ).fetchone()

        sender_total = int(
            conn.execute(
                f"""
                SELECT COUNT(*) AS c FROM (
                  SELECT from_addr FROM messages
                  WHERE from_addr IS NOT NULL AND from_addr != '' AND {eligible}
                  GROUP BY from_addr
                )
                """,
                keep_params,
            ).fetchone()["c"]
        )
        domain_total = int(
            conn.execute(
                f"""
                SELECT COUNT(*) AS c FROM (
                  SELECT from_domain FROM messages
                  WHERE from_domain IS NOT NULL AND from_domain != '' AND {eligible}
                  GROUP BY from_domain
                )
                """,
                keep_params,
            ).fetchone()["c"]
        )

        top_senders = [
            annotate_sender(dict(r))
            for r in conn.execute(
                f"""
                SELECT from_addr, from_domain,
                       COUNT(*) AS cnt,
                       SUM(size) AS bytes,
                       SUM(CASE WHEN list_unsubscribe = 1 THEN 1 ELSE 0 END) AS list_unsub_cnt
                FROM messages
                WHERE from_addr IS NOT NULL AND from_addr != '' AND {eligible}
                GROUP BY from_addr
                ORDER BY cnt DESC
                LIMIT ? OFFSET ?
                """,
                [*keep_params, top_n, sender_offset],
            ).fetchall()
        ]
        top_domains = [
            annotate_domain(dict(r))
            for r in conn.execute(
                f"""
                SELECT from_domain,
                       COUNT(*) AS cnt,
                       SUM(size) AS bytes,
                       SUM(CASE WHEN list_unsubscribe = 1 THEN 1 ELSE 0 END) AS list_unsub_cnt
                FROM messages
                WHERE from_domain IS NOT NULL AND from_domain != '' AND {eligible}
                GROUP BY from_domain
                ORDER BY cnt DESC
                LIMIT ? OFFSET ?
                """,
                [*keep_params, top_n, domain_offset],
            ).fetchall()
        ]
        folders = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT folder, COUNT(*) AS cnt, SUM(size) AS bytes
                FROM messages
                WHERE {eligible}
                GROUP BY folder
                ORDER BY cnt DESC
                """,
                keep_params,
            ).fetchall()
        ]

        age_buckets = []
        age_defs = [
            ("last_30d", "Last 30 days", None, "date_ts >= ?", (now_ts - 30 * 86400,)),
            (
                "30d_to_1y",
                "30 days – 1 year",
                None,
                "date_ts < ? AND date_ts >= ?",
                (now_ts - 30 * 86400, now_ts - 365 * 86400),
            ),
            (
                "older_1y",
                "Older than 1 year",
                365,
                "date_ts < ? OR date_ts IS NULL",
                (now_ts - 365 * 86400,),
            ),
            (
                "older_2y",
                "Older than 2 years",
                730,
                "date_ts < ? OR date_ts IS NULL",
                (now_ts - 730 * 86400,),
            ),
            (
                "older_5y",
                "Older than 5 years",
                1825,
                "date_ts < ? OR date_ts IS NULL",
                (now_ts - 1825 * 86400,),
            ),
        ]
        for key, label, older_than_days, sql, params in age_defs:
            row = conn.execute(
                f"""
                SELECT COUNT(*) AS cnt, COALESCE(SUM(size),0) AS bytes
                FROM messages
                WHERE ({sql}) AND {eligible}
                """,
                [*params, *keep_params],
            ).fetchone()
            age_buckets.append(
                {
                    "bucket": key,
                    "label": label,
                    "older_than_days": older_than_days,
                    "suggestable": older_than_days is not None,
                    "cnt": row["cnt"],
                    "bytes": row["bytes"],
                }
            )
        list_unsub = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt, COALESCE(SUM(size),0) AS bytes
            FROM messages WHERE list_unsubscribe = 1 AND {eligible}
            """,
            keep_params,
        ).fetchone()

        # Broader-rule preview: List-Unsubscribe + age cutoffs
        broader_options = []
        for days, label in (
            (30, "30 days"),
            (365, "1 year"),
            (730, "2 years"),
            (1825, "5 years"),
        ):
            cutoff = now_ts - days * 86400
            row = conn.execute(
                f"""
                SELECT COUNT(*) AS cnt, COALESCE(SUM(size),0) AS bytes
                FROM messages
                WHERE list_unsubscribe = 1
                  AND (date_ts IS NULL OR date_ts < ?)
                  AND {eligible}
                """,
                [cutoff, *keep_params],
            ).fetchone()
            broader_options.append(
                {
                    "kind": "list_unsubscribe_older_than",
                    "value": days,
                    "label": f"List-Unsubscribe older than {label}",
                    "cnt": row["cnt"],
                    "bytes": row["bytes"],
                    "bytes_human": format_size(row["bytes"]),
                }
            )

        large = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT folder, uid, from_addr, subject, date_ts, size
                FROM messages
                WHERE {eligible}
                ORDER BY size DESC
                LIMIT 25
                """,
                keep_params,
            ).fetchall()
        ]

        staged_addrs = {r.from_address for r in ruleset.stage if r.from_address}
        staged_domains = {r.from_domain for r in ruleset.stage if r.from_domain}

        inbox_row = conn.execute(
            """
            SELECT COUNT(*) AS c, COALESCE(SUM(size),0) AS s
            FROM messages WHERE lower(folder) = 'inbox'
            """
        ).fetchone()

        triage = build_triage(
            conn, eligible, keep_params, self_email=self_email, keep_sample_n=120
        )

        return {
            "total_messages": total["c"],
            "total_bytes": total["s"],
            "total_bytes_human": format_size(total["s"]),
            "inbox_messages": inbox_row["c"],
            "inbox_bytes": inbox_row["s"],
            "inbox_bytes_human": format_size(inbox_row["s"]),
            "cleanup_eligible_messages": eligible_total["c"],
            "cleanup_eligible_bytes": eligible_total["s"],
            "cleanup_eligible_bytes_human": format_size(eligible_total["s"]),
            "keep_rule_count": len(ruleset.keep),
            "self_email": self_email,
            "triage": triage,
            "top_n": top_n,
            "sender_offset": sender_offset,
            "domain_offset": domain_offset,
            "sender_total": sender_total,
            "domain_total": domain_total,
            "senders_has_more": sender_offset + len(top_senders) < sender_total,
            "domains_has_more": domain_offset + len(top_domains) < domain_total,
            "top_senders": top_senders,
            "top_domains": top_domains,
            "folders": folders,
            "age_buckets": age_buckets,
            "list_unsubscribe": dict(list_unsub),
            "broader_options": broader_options,
            "largest": large,
            "existing_stage_addresses": sorted(staged_addrs),
            "existing_stage_domains": sorted(staged_domains),
        }
    finally:
        conn.close()


def propose_cleanup_selections(
    profile: Profile,
    *,
    min_count: int = 20,
    limit: int = 50,
    kinds: list[str] | None = None,
    heuristic_only: bool = False,
    skip_existing_stage_rules: bool = True,
) -> list[dict[str, Any]]:
    """
    Build Insights-style selections for the next cleanup batch.
    Does not move mail — caller creates rules and sends user to review.
    """
    kinds = kinds or ["from_address", "from_domain"]
    min_count = max(1, int(min_count))
    limit = max(1, min(int(limit), 200))
    data = discover(profile, top_n=500, sender_offset=0, domain_offset=0)
    self_email = (profile.email or "").lower()
    staged_addrs = set(data.get("existing_stage_addresses") or [])
    staged_domains = set(data.get("existing_stage_domains") or [])
    selections: list[dict[str, Any]] = []

    if "from_address" in kinds:
        for row in data["top_senders"]:
            if len(selections) >= limit:
                break
            addr = (row.get("from_addr") or "").lower()
            if not addr or addr == self_email:
                continue
            if int(row.get("cnt") or 0) < min_count:
                continue
            if skip_existing_stage_rules and addr in staged_addrs:
                continue
            if heuristic_only and not row.get("heuristic_likely"):
                continue
            selections.append(
                {
                    "kind": "from_address",
                    "value": addr,
                    "cnt": row["cnt"],
                    "flags": row.get("heuristic_flags") or [],
                }
            )

    if "from_domain" in kinds and len(selections) < limit:
        for row in data["top_domains"]:
            if len(selections) >= limit:
                break
            domain = (row.get("from_domain") or "").lower()
            if not domain:
                continue
            if self_email and domain == self_email.split("@")[-1]:
                continue
            if int(row.get("cnt") or 0) < min_count:
                continue
            if skip_existing_stage_rules and domain in staged_domains:
                continue
            if heuristic_only and not row.get("heuristic_likely"):
                continue
            selections.append(
                {
                    "kind": "from_domain",
                    "value": domain,
                    "cnt": row["cnt"],
                    "flags": row.get("heuristic_flags") or [],
                }
            )
    return selections

def _preview_folder_scope(profile: Profile | None, rule: Rule) -> tuple[str, list[Any]]:
    """Match stage_rules(): profile folder scope unless the rule pins a folder."""
    if profile is None:
        return "", []
    return profile.stage_folder_sql(rule)


def preview_rule(
    profile: Profile,
    rule: Rule,
    sample_n: int | None = None,
    apply_keep_exclusion: bool = True,
) -> dict[str, Any]:
    ruleset = load_rules(profile.rules_path)
    return preview_rule_with_ruleset(
        profile.db_path,
        rule,
        ruleset if apply_keep_exclusion else RuleSet(),
        sample_n or profile.preview_sample_n,
        profile=profile,
    )


def preview_rule_with_ruleset(
    db_path,
    rule: Rule,
    ruleset: RuleSet,
    sample_n: int,
    conn: sqlite3.Connection | None = None,
    *,
    include_samples: bool = True,
    profile: Profile | None = None,
    keep_sql: str | None = None,
    keep_params: list[Any] | None = None,
) -> dict[str, Any]:
    owns_conn = conn is None
    if owns_conn:
        conn = init_db(db_path)
    assert conn is not None
    try:
        now_ts = int(time.time())
        where, params = rule_sql_clauses(rule, now_ts)
        if keep_sql is None:
            keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
        keep_params = keep_params or []
        folder_sql, folder_params = _preview_folder_scope(profile, rule)
        full_where = f"({where}) AND ({keep_sql}){folder_sql}"
        all_params = params + keep_params + folder_params

        agg = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt,
                   COALESCE(SUM(size),0) AS bytes,
                   SUM(CASE WHEN has_attachment = 1 THEN 1 ELSE 0 END) AS with_attachment,
                   SUM(CASE WHEN has_attachment IS NULL THEN 1 ELSE 0 END) AS attachment_unknown,
                   SUM(CASE WHEN size >= 102400 THEN 1 ELSE 0 END) AS large_100k
            FROM messages WHERE {full_where}
            """,
            all_params,
        ).fetchone()

        samples: list[dict[str, Any]] = []
        if include_samples and sample_n > 0:
            samples = [
                _sample_row(r)
                for r in conn.execute(
                    f"""
                    SELECT {", ".join(SAMPLE_COLS)}
                    FROM messages
                    WHERE {full_where}
                    ORDER BY date_ts IS NULL, date_ts ASC
                    LIMIT ?
                    """,
                    all_params + [sample_n],
                ).fetchall()
            ]

        return {
            "rule_id": rule.id,
            "label": rule.label,
            "match_count": agg["cnt"],
            "total_bytes": agg["bytes"],
            "total_bytes_human": format_size(agg["bytes"]),
            "with_attachment": int(agg["with_attachment"] or 0),
            "attachment_unknown": int(agg["attachment_unknown"] or 0),
            "large_100k": int(agg["large_100k"] or 0),
            "samples": samples,
            "note": "Samples are metadata from the local index only (no body fetch).",
            "criteria": {
                "from_domain": rule.from_domain,
                "from_address": rule.from_address,
                "older_than_days": rule.older_than_days,
                "folder": rule.folder or (
                    profile.stage_scope_label()
                    if profile and rule.folder is None and profile.effective_stage_folders()
                    else None
                ),
                "subject_contains": rule.subject_contains,
                "has_list_unsubscribe": rule.has_list_unsubscribe,
                "min_size": rule.min_size,
            },
            "stage_scope": (
                profile.stage_scope_label(rule.folder)
                if profile
                else (rule.folder or "all folders")
            ),
        }
    finally:
        if owns_conn:
            conn.close()


def preview_all_stage_rules(
    profile: Profile,
    rule_ids: list[str] | None = None,
    *,
    include_samples: bool = True,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    from mail_janitor.rules import active_stage_rules

    ruleset = load_rules(profile.rules_path)
    pool = active_stage_rules(ruleset) if active_only else list(ruleset.stage)
    wanted = set(rule_ids) if rule_ids is not None else None
    rules = [
        rule
        for rule in pool
        if wanted is None or rule.id in wanted
    ]
    if wanted is not None:
        # Preserve caller order when focusing a batch; allow archived if explicitly asked
        by_id = {r.id: r for r in ruleset.stage}
        rules = [by_id[rid] for rid in rule_ids or [] if rid in by_id]
    now_ts = int(time.time())
    keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
    conn = init_db(profile.db_path)
    try:
        return [
            preview_rule_with_ruleset(
                profile.db_path,
                rule,
                ruleset,
                profile.preview_sample_n if include_samples else 0,
                conn=conn,
                include_samples=include_samples,
                profile=profile,
                keep_sql=keep_sql,
                keep_params=keep_params,
            )
            for rule in rules
        ]
    finally:
        conn.close()


def _sample_row(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    d["date_human"] = format_ts(d.get("date_ts"))
    d["size_human"] = format_size(d.get("size"))
    return d

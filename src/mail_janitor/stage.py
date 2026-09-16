"""Stage matched UIDs for review — does not touch the mailbox."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from mail_janitor.audit import audit_log
from mail_janitor.config import Profile
from mail_janitor.db import init_db, staged_count
from mail_janitor.rules import active_stage_rules, keep_exclusion_sql, load_rules, rule_sql_clauses


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stage_folder_sql(profile: Profile, rule) -> tuple[str, list[Any]]:
    """Rules without folder only match profile's configured cleanup folders."""
    return profile.stage_folder_sql(rule)


def stage_rules(
    profile: Profile,
    rule_ids: list[str] | None = None,
    clear: bool = False,
    progress_cb: Any | None = None,
) -> dict:
    ruleset = load_rules(profile.rules_path)
    rules = active_stage_rules(ruleset)
    if rule_ids:
        wanted = set(rule_ids)
        rules = [r for r in rules if r.id in wanted]
        missing = wanted - {r.id for r in rules}
        # Allow targeting archived ids explicitly (reactivate path later)
        if missing:
            all_by_id = {r.id: r for r in ruleset.stage}
            extras = [all_by_id[i] for i in missing if i in all_by_id]
            if len(extras) + len(rules) < len(wanted):
                still = wanted - {r.id for r in rules} - {r.id for r in extras}
                if still:
                    raise ValueError(f"Unknown stage rule ids: {sorted(still)}")
            rules = rules + extras

    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
    staged = 0
    total_rules = len(rules)

    def report(**kw: Any) -> None:
        if progress_cb:
            progress_cb(rules_total=total_rules, **kw)

    try:
        if clear:
            conn.execute("DELETE FROM staged")

        report(rules_done=0, phase="start")
        for i, rule in enumerate(rules):
            where, params = rule_sql_clauses(rule, now_ts)
            folder_sql, folder_params = _stage_folder_sql(profile, rule)
            sql = f"""
                INSERT INTO staged (folder, uid, rule_id, reason, included, staged_at)
                SELECT folder, uid, ?, ?, 1, ?
                FROM messages
                WHERE ({where}) AND ({keep_sql}){folder_sql}
                ON CONFLICT(folder, uid) DO UPDATE SET
                    rule_id=excluded.rule_id,
                    reason=excluded.reason,
                    included=1,
                    staged_at=excluded.staged_at
            """
            reason = rule.label or rule.id
            cur = conn.execute(
                sql, [rule.id, reason, _now()] + params + keep_params + folder_params
            )
            staged += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            if (i + 1) % 5 == 0 or i + 1 == total_rules:
                conn.commit()
            report(
                rules_done=i + 1,
                phase="rule",
                rule_id=rule.id,
                rows_touched=staged,
            )

        conn.commit()
        total = staged_count(conn, included_only=True)
        result = {
            "rules_applied": [r.id for r in rules],
            "rows_touched": staged,
            "staged_included": total,
        }
        audit_log(profile.audit_path, "stage", account=profile.name, **result)
        return result
    finally:
        conn.close()


def set_staged_included(profile: Profile, folder: str, uid: int, included: bool) -> None:
    conn = init_db(profile.db_path)
    try:
        conn.execute(
            "UPDATE staged SET included = ? WHERE folder = ? AND uid = ?",
            (1 if included else 0, folder, uid),
        )
        conn.commit()
    finally:
        conn.close()


def set_many_included(profile: Profile, items: list[tuple[str, int]], included: bool) -> int:
    conn = init_db(profile.db_path)
    try:
        conn.executemany(
            "UPDATE staged SET included = ? WHERE folder = ? AND uid = ?",
            [(1 if included else 0, f, u) for f, u in items],
        )
        conn.commit()
        return len(items)
    finally:
        conn.close()


def set_all_staged_included(
    profile: Profile,
    included: bool,
    *,
    from_domain: str | None = None,
    rule_id: str | None = None,
    q: str | None = None,
) -> int:
    """Set included for all staged rows matching optional filters (entire set, not one page)."""
    conn = init_db(profile.db_path)
    try:
        clauses = ["1=1"]
        params: list = []
        if from_domain:
            clauses.append(
                "EXISTS (SELECT 1 FROM messages m WHERE m.folder = staged.folder "
                "AND m.uid = staged.uid AND lower(m.from_domain) = ?)"
            )
            params.append(from_domain.lower())
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if q:
            clauses.append(
                "EXISTS (SELECT 1 FROM messages m WHERE m.folder = staged.folder "
                "AND m.uid = staged.uid AND (lower(m.subject) LIKE ? OR lower(m.from_addr) LIKE ?))"
            )
            params.extend([f"%{q.lower()}%", f"%{q.lower()}%"])
        where = " AND ".join(clauses)
        cur = conn.execute(
            f"UPDATE staged SET included = ? WHERE {where}",
            [1 if included else 0] + params,
        )
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def clear_staged(profile: Profile) -> None:
    conn = init_db(profile.db_path)
    try:
        conn.execute("DELETE FROM staged")
        conn.commit()
        audit_log(profile.audit_path, "stage_clear", account=profile.name)
    finally:
        conn.close()


def stage_by_confidence(
    profile: Profile,
    *,
    confidence: str = "junk",
    limit: int = 500,
    clear: bool = False,
) -> dict[str, Any]:
    """Stage cleanup-eligible messages matching a triage confidence (default: junk).

    Scores metadata in-process (no LLM). Keep-rule matches are excluded.
    """
    from mail_janitor.heuristics import score_message

    confidence = (confidence or "junk").strip().lower()
    if confidence not in ("junk", "uncertain", "keep"):
        raise ValueError("confidence must be junk, uncertain, or keep")
    limit = max(1, min(int(limit), 2000))

    ruleset = load_rules(profile.rules_path)
    conn = init_db(profile.db_path)
    now_ts = int(time.time())
    try:
        if clear:
            conn.execute("DELETE FROM staged")

        keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
        folder_sql = ""
        folder_params: list[Any] = []
        stage_folders = profile.effective_stage_folders()
        if stage_folders:
            placeholders = ", ".join("?" for _ in stage_folders)
            folder_sql = f" AND folder IN ({placeholders})"
            folder_params = list(stage_folders)
        rows = conn.execute(
            f"""
            SELECT folder, uid, from_addr, from_domain, subject, date_ts, size,
                   list_unsubscribe
            FROM messages
            WHERE ({keep_sql}){folder_sql}
            ORDER BY date_ts IS NULL DESC, date_ts ASC
            """,
            keep_params + folder_params,
        ).fetchall()

        picked: list[tuple[Any, ...]] = []
        scanned = 0
        for raw in rows:
            scanned += 1
            msg = dict(raw)
            sc = score_message(msg)
            if sc["confidence"] != confidence:
                continue
            picked.append(
                (
                    msg["folder"],
                    int(msg["uid"]),
                    f"triage-{confidence}",
                    f"Triage: {confidence} (score {sc['score']})",
                    1,
                    _now(),
                )
            )
            if len(picked) >= limit:
                break

        if picked:
            conn.executemany(
                """
                INSERT INTO staged (folder, uid, rule_id, reason, included, staged_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(folder, uid) DO UPDATE SET
                    rule_id=excluded.rule_id,
                    reason=excluded.reason,
                    included=1,
                    staged_at=excluded.staged_at
                """,
                picked,
            )
            conn.commit()

        total = staged_count(conn, included_only=True)
        result = {
            "confidence": confidence,
            "limit": limit,
            "scanned": scanned,
            "matched": len(picked),
            "rows_touched": len(picked),
            "staged_included": total,
            "rules_applied": [f"triage-{confidence}"],
        }
        audit_log(profile.audit_path, "stage_triage", account=profile.name, **result)
        return result
    finally:
        conn.close()


def list_staged(
    profile: Profile,
    included_only: bool = True,
    limit: int = 200,
    offset: int = 0,
    from_domain: str | None = None,
    rule_id: str | None = None,
    q: str | None = None,
) -> tuple[list[dict], int]:
    conn = init_db(profile.db_path)
    try:
        clauses = ["1=1"]
        params: list = []
        if included_only:
            clauses.append("s.included = 1")
        if from_domain:
            clauses.append("lower(m.from_domain) = ?")
            params.append(from_domain.lower())
        if rule_id:
            clauses.append("s.rule_id = ?")
            params.append(rule_id)
        if q:
            clauses.append("(lower(m.subject) LIKE ? OR lower(m.from_addr) LIKE ?)")
            params.extend([f"%{q.lower()}%", f"%{q.lower()}%"])
        where = " AND ".join(clauses)
        total = conn.execute(
            f"""
            SELECT COUNT(*) AS c
            FROM staged s
            JOIN messages m ON m.folder = s.folder AND m.uid = s.uid
            WHERE {where}
            """,
            params,
        ).fetchone()["c"]
        rows = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT s.folder, s.uid, s.rule_id, s.reason, s.included, s.staged_at,
                       m.from_addr, m.from_domain, m.subject, m.date_ts, m.size,
                       m.list_unsubscribe, m.message_id, m.has_attachment
                FROM staged s
                JOIN messages m ON m.folder = s.folder AND m.uid = s.uid
                WHERE {where}
                ORDER BY m.date_ts ASC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            ).fetchall()
        ]
        return rows, int(total)
    finally:
        conn.close()

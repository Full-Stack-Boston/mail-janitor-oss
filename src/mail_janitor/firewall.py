"""Firewall runtime: poll watch folder, quarantine matches, release to Inbox."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from mail_janitor.audit import audit_log
from mail_janitor.config import Profile
from mail_janitor.db import init_db
from mail_janitor.firewall_policy import (
    Decision,
    evaluate_message,
    load_firewall,
)
from mail_janitor.providers import get_provider
from mail_janitor.providers.base import chunked, with_backoff


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def firewall_path(profile: Profile):
    return profile.path / "firewall.yaml"


def get_firewall_progress(conn, watch_folder: str) -> tuple[int, int | None]:
    row = conn.execute(
        "SELECT last_uid, uidvalidity FROM firewall_state WHERE watch_folder = ?",
        (watch_folder,),
    ).fetchone()
    if not row:
        return 0, None
    return int(row["last_uid"]), row["uidvalidity"]


def set_firewall_progress(
    conn, watch_folder: str, last_uid: int, uidvalidity: int | None
) -> None:
    conn.execute(
        """
        INSERT INTO firewall_state (watch_folder, last_uid, uidvalidity, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(watch_folder) DO UPDATE SET
            last_uid=excluded.last_uid,
            uidvalidity=excluded.uidvalidity,
            updated_at=excluded.updated_at
        """,
        (watch_folder, last_uid, uidvalidity, _now()),
    )


def firewall_status(profile: Profile) -> dict[str, Any]:
    cfg = load_firewall(firewall_path(profile))
    conn = init_db(profile.db_path)
    try:
        last_uid, uidvalidity = get_firewall_progress(conn, cfg.watch_folder)
        held = conn.execute(
            """
            SELECT COUNT(*) AS c FROM firewall_actions
            WHERE action = 'quarantine' AND released = 0
            """
        ).fetchone()["c"]
        recent = [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, action, reason, from_addr, subject, created_at, released
                FROM firewall_actions
                ORDER BY id DESC LIMIT 20
                """
            ).fetchall()
        ]
        return {
            "enabled": cfg.enabled,
            "watch_folder": cfg.watch_folder,
            "quarantine_folder": cfg.quarantine_folder,
            "poll_seconds": cfg.poll_seconds,
            "heuristic_quarantine": cfg.heuristic_quarantine,
            "allow_rules": len(cfg.allow),
            "block_rules": len(cfg.block),
            "last_uid": last_uid,
            "uidvalidity": uidvalidity,
            "quarantined_held": held,
            "recent": recent,
            "note": (
                "Quarantine is NOT Trash and NOT ready2delete. "
                "Release restores mail to the watch folder."
            ),
        }
    finally:
        conn.close()


def process_once(profile: Profile, *, dry_run: bool = False) -> dict[str, Any]:
    """Fetch new UIDs since last watermark and apply firewall decisions."""
    cfg = load_firewall(firewall_path(profile))
    if not cfg.enabled:
        return {"ok": False, "error": "firewall disabled in firewall.yaml"}

    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    conn = init_db(profile.db_path)
    stats = {
        "seen": 0,
        "passed": 0,
        "quarantined": 0,
        "errors": [],
        "dry_run": dry_run,
        "decisions": [],
    }

    try:
        client.ensure_folder(cfg.quarantine_folder)
        exists, uidvalidity = with_backoff(
            lambda: client.select(cfg.watch_folder, readonly=False)
        )
        last_uid, prev_validity = get_firewall_progress(conn, cfg.watch_folder)
        if prev_validity is not None and uidvalidity is not None and prev_validity != uidvalidity:
            last_uid = 0

        # First run: set watermark to current max without acting on backlog
        if last_uid == 0 and exists > 0:
            uids_all = with_backoff(lambda: client.uid_search_all_above(0))
            if uids_all:
                last_uid = max(uids_all)
                set_firewall_progress(conn, cfg.watch_folder, last_uid, uidvalidity)
                conn.commit()
                audit_log(
                    profile.audit_path,
                    "firewall_init",
                    account=profile.name,
                    watch_folder=cfg.watch_folder,
                    last_uid=last_uid,
                    skipped_backlog=len(uids_all),
                )
                return {
                    "ok": True,
                    "initialized": True,
                    "last_uid": last_uid,
                    "skipped_backlog": len(uids_all),
                    "message": (
                        "Watermark set at current mailbox tip — "
                        "only *new* mail after this will be evaluated. "
                        "Backlog stays for Mail Janitor."
                    ),
                    **stats,
                }

        uids = with_backoff(lambda: client.uid_search_all_above(last_uid))
        if exists == 0:
            uids = []

        max_uid = last_uid
        for batch in chunked(uids, min(100, profile.scan_batch_size)):
            rows = with_backoff(lambda b=batch: client.fetch_headers(b))
            by_uid = {int(r["uid"]): r for r in rows}
            for uid in batch:
                row = by_uid.get(uid)
                if not row:
                    continue
                msg = {
                    "folder": cfg.watch_folder,
                    "uid": uid,
                    "from_addr": row.get("from_addr") or "",
                    "from_domain": row.get("from_domain") or "",
                    "subject": row.get("subject") or "",
                    "list_unsubscribe": int(row.get("list_unsubscribe") or 0),
                    "size": int(row.get("size") or 0),
                    "message_id": row.get("message_id") or "",
                    "date_ts": row.get("date_ts"),
                }
                decision: Decision = evaluate_message(msg, cfg)
                stats["seen"] += 1
                stats["decisions"].append(
                    {
                        "uid": uid,
                        "from": msg["from_addr"],
                        "action": decision.action,
                        "reason": decision.reason,
                    }
                )
                max_uid = max(max_uid, uid)

                if decision.action == "pass":
                    stats["passed"] += 1
                    continue

                # quarantine
                dest_uid = None
                if not dry_run:
                    try:
                        dest_uid = with_backoff(
                            lambda u=uid: client.move_uid(u, cfg.quarantine_folder)
                        )
                    except Exception as e:
                        stats["errors"].append({"uid": uid, "error": str(e)})
                        continue
                    conn.execute(
                        """
                        INSERT INTO firewall_actions (
                            action, reason, rule_id, source_folder, source_uid,
                            dest_folder, dest_uid, message_id, from_addr, from_domain,
                            subject, date_ts, size, created_at, released
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                        """,
                        (
                            "quarantine",
                            decision.reason,
                            decision.rule_id,
                            cfg.watch_folder,
                            uid,
                            cfg.quarantine_folder,
                            dest_uid,
                            msg["message_id"],
                            msg["from_addr"],
                            msg["from_domain"],
                            msg["subject"],
                            msg.get("date_ts"),
                            msg["size"],
                            _now(),
                        ),
                    )
                    audit_log(
                        profile.audit_path,
                        "firewall_quarantine",
                        account=profile.name,
                        source_folder=cfg.watch_folder,
                        source_uid=uid,
                        dest_folder=cfg.quarantine_folder,
                        dest_uid=dest_uid,
                        reason=decision.reason,
                        rule_id=decision.rule_id,
                        from_addr=msg["from_addr"],
                        subject=msg["subject"],
                    )
                stats["quarantined"] += 1

            if not dry_run:
                set_firewall_progress(conn, cfg.watch_folder, max_uid, uidvalidity)
                conn.commit()
                # After MOVE, re-select watch folder (Yahoo may deselect)
                with_backoff(lambda: client.select(cfg.watch_folder, readonly=False))

        if not dry_run and max_uid > last_uid:
            set_firewall_progress(conn, cfg.watch_folder, max_uid, uidvalidity)
            conn.commit()

        return {"ok": True, **stats, "last_uid": max_uid}
    finally:
        client.close()
        conn.close()


def watch_loop(
    profile: Profile,
    *,
    once: bool = False,
    dry_run: bool = False,
    max_iterations: int | None = None,
) -> dict[str, Any]:
    """Poll forever (or once). Safe alongside Mail Janitor apply (separate process)."""
    cfg = load_firewall(firewall_path(profile))
    iterations = 0
    last: dict[str, Any] = {}
    while True:
        last = process_once(profile, dry_run=dry_run)
        iterations += 1
        if once or (max_iterations is not None and iterations >= max_iterations):
            return last
        time.sleep(cfg.poll_seconds)


def release_quarantine(
    profile: Profile,
    *,
    action_ids: list[int] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Move quarantined messages back to the watch folder."""
    cfg = load_firewall(firewall_path(profile))
    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    conn = init_db(profile.db_path)
    restored = 0
    errors: list[dict] = []
    try:
        with_backoff(lambda: client.select(cfg.quarantine_folder, readonly=False))
        sql = """
            SELECT * FROM firewall_actions
            WHERE action = 'quarantine' AND released = 0 AND dest_uid IS NOT NULL
        """
        params: list[Any] = []
        if action_ids:
            placeholders = ",".join("?" for _ in action_ids)
            sql += f" AND id IN ({placeholders})"
            params.extend(action_ids)
        sql += " ORDER BY id ASC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        for row in rows:
            uid = int(row["dest_uid"])
            try:
                new_uid = with_backoff(
                    lambda u=uid: client.move_uid(u, cfg.watch_folder)
                )
                conn.execute(
                    """
                    UPDATE firewall_actions
                    SET released = 1, released_at = ?
                    WHERE id = ?
                    """,
                    (_now(), row["id"]),
                )
                audit_log(
                    profile.audit_path,
                    "firewall_release",
                    account=profile.name,
                    action_id=row["id"],
                    from_folder=cfg.quarantine_folder,
                    from_uid=uid,
                    to_folder=cfg.watch_folder,
                    to_uid=new_uid,
                    from_addr=row.get("from_addr"),
                )
                restored += 1
            except Exception as e:
                errors.append({"id": row["id"], "uid": uid, "error": str(e)})
        conn.commit()
    finally:
        client.close()
        conn.close()
    return {"restored": restored, "errors": errors, "to_folder": cfg.watch_folder}


def list_quarantine(profile: Profile, limit: int = 50) -> list[dict]:
    conn = init_db(profile.db_path)
    try:
        return [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, reason, rule_id, from_addr, from_domain, subject,
                       size, created_at, dest_uid
                FROM firewall_actions
                WHERE action = 'quarantine' AND released = 0
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]
    finally:
        conn.close()

"""Move staged messages to ready2delete / Trash — never expunge."""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from mail_janitor.audit import audit_log
from mail_janitor.config import Profile
from mail_janitor.db import init_db
from mail_janitor.parse_headers import format_size, format_ts
from mail_janitor.providers import get_provider
from mail_janitor.providers.base import with_backoff


CONFIRM_READY = "MOVE TO READY2DELETE"
CONFIRM_KEPT = "MOVE TO INTENTIONALLY KEPT"
CONFIRM_TRASH = "MOVE TO TRASH"
CONFIRM_UNDO = "UNDO FROM READY2DELETE"
CONFIRM_UNDO_KEPT = "UNDO FROM INTENTIONALLY KEPT"
KEEP_APPLY_RULE_ID = "keep-apply"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def preflight_staged(profile: Profile, *, detail: bool = True) -> dict[str, Any]:
    """Summary of included staged messages.

    detail=False skips by_rule / top_senders (expensive with thousands of rules)
    and is used on hot paths like /review and /api/apply/status.
    """
    conn = init_db(profile.db_path)
    try:
        agg = conn.execute(
            """
            SELECT COUNT(*) AS cnt, COALESCE(SUM(m.size),0) AS bytes,
                   MIN(m.date_ts) AS min_ts, MAX(m.date_ts) AS max_ts
            FROM staged s
            JOIN messages m ON m.folder = s.folder AND m.uid = s.uid
            WHERE s.included = 1
            """
        ).fetchone()
        out: dict[str, Any] = {
            "count": agg["cnt"],
            "bytes": agg["bytes"],
            "bytes_human": format_size(agg["bytes"]),
            "date_min": format_ts(agg["min_ts"]),
            "date_max": format_ts(agg["max_ts"]),
            "dest_folder": profile.ready_folder,
            "confirm_phrase": CONFIRM_READY,
        }
        if not detail:
            return out
        out["by_rule"] = [
            dict(r)
            for r in conn.execute(
                """
                SELECT s.rule_id, COUNT(*) AS cnt, COALESCE(SUM(m.size),0) AS bytes
                FROM staged s
                JOIN messages m ON m.folder = s.folder AND m.uid = s.uid
                WHERE s.included = 1
                GROUP BY s.rule_id
                ORDER BY cnt DESC
                """
            ).fetchall()
        ]
        out["top_senders"] = [
            dict(r)
            for r in conn.execute(
                """
                SELECT m.from_addr, COUNT(*) AS cnt, COALESCE(SUM(m.size),0) AS bytes
                FROM staged s
                JOIN messages m ON m.folder = s.folder AND m.uid = s.uid
                WHERE s.included = 1
                GROUP BY m.from_addr
                ORDER BY cnt DESC
                LIMIT 15
                """
            ).fetchall()
        ]
        return out
    finally:
        conn.close()


def _record_move(
    conn: Any,
    profile: Profile,
    row: dict[str, Any],
    dest_folder: str,
    dest_uid: int | None,
) -> None:
    folder = row["folder"]
    uid = int(row["uid"])
    conn.execute(
        """
        INSERT INTO moves (
            source_folder, source_uid, dest_folder, dest_uid,
            message_id, from_addr, subject, date_ts, size, rule_id, moved_at, undone
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            folder,
            uid,
            dest_folder,
            dest_uid,
            row.get("message_id"),
            row.get("from_addr"),
            row.get("subject"),
            row.get("date_ts"),
            row.get("size"),
            row.get("rule_id"),
            _now(),
        ),
    )
    conn.execute("DELETE FROM staged WHERE folder = ? AND uid = ?", (folder, uid))
    conn.execute("DELETE FROM keeper_seen WHERE folder = ? AND uid = ?", (folder, uid))
    conn.execute("DELETE FROM messages WHERE folder = ? AND uid = ?", (folder, uid))
    if dest_uid is not None:
        conn.execute(
            """
            INSERT OR REPLACE INTO messages (
                folder, uid, message_id, from_addr, from_domain, subject,
                date_ts, date_raw, size, flags, list_unsubscribe, scanned_at
            ) VALUES (?, ?, ?, ?, '', ?, ?, '', ?, '', 0, ?)
            """,
            (
                dest_folder,
                dest_uid,
                row.get("message_id"),
                row.get("from_addr"),
                row.get("subject"),
                row.get("date_ts"),
                row.get("size"),
                _now(),
            ),
        )
    audit_log(
        profile.audit_path,
        "move",
        account=profile.name,
        source_folder=folder,
        source_uid=uid,
        dest_folder=dest_folder,
        dest_uid=dest_uid,
        from_addr=row.get("from_addr"),
        subject=row.get("subject"),
        date_ts=row.get("date_ts"),
        size=row.get("size"),
        rule_id=row.get("rule_id"),
    )


def _is_conn_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(
        s in text
        for s in (
            "ssl",
            "eof",
            "broken pipe",
            "connection",
            "timed out",
            "timeout",
            "socket",
            "abort",
            "reset",
        )
    )


def preflight_kept_inbox(profile: Profile, *, detail: bool = True) -> dict[str, Any]:
    """Inbox messages matching keep rules — candidates for apply_to_kept."""
    from mail_janitor.keeper import keep_inclusion_sql
    from mail_janitor.rules import load_rules

    ruleset = load_rules(profile.rules_path)
    now_ts = int(time.time())
    incl_sql, incl_params = keep_inclusion_sql(ruleset, now_ts)
    empty: dict[str, Any] = {
        "count": 0,
        "bytes": 0,
        "bytes_human": format_size(0),
        "date_min": "",
        "date_max": "",
        "dest_folder": profile.kept_folder,
        "source_folder": profile.inbox_folder,
        "confirm_phrase": CONFIRM_KEPT,
    }
    if incl_sql == "0":
        return empty

    conn = init_db(profile.db_path)
    try:
        where = f"lower(folder) = lower(?) AND ({incl_sql})"
        params = [profile.inbox_folder] + incl_params
        agg = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt, COALESCE(SUM(size),0) AS bytes,
                   MIN(date_ts) AS min_ts, MAX(date_ts) AS max_ts
            FROM messages WHERE {where}
            """,
            params,
        ).fetchone()
        out: dict[str, Any] = {
            "count": int(agg["cnt"] or 0),
            "bytes": int(agg["bytes"] or 0),
            "bytes_human": format_size(agg["bytes"]),
            "date_min": format_ts(agg["min_ts"]),
            "date_max": format_ts(agg["max_ts"]),
            "dest_folder": profile.kept_folder,
            "source_folder": profile.inbox_folder,
            "confirm_phrase": CONFIRM_KEPT,
        }
        if not detail:
            return out
        out["top_senders"] = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT from_addr, COUNT(*) AS cnt, COALESCE(SUM(size),0) AS bytes
                FROM messages WHERE {where}
                GROUP BY from_addr
                ORDER BY cnt DESC
                LIMIT 15
                """,
                params,
            ).fetchall()
        ]
        return out
    finally:
        conn.close()


def _move_batch(
    client: Any,
    profile: Profile,
    conn: Any,
    folder: str,
    batch_rows: list[dict[str, Any]],
    dest_folder: str,
    errors: list[dict],
) -> tuple[int, Exception | None]:
    """Move one folder batch; fall back to per-UID on batch failure.

    Returns (moved_count, connection_error_or_None).
    """
    uids = [int(r["uid"]) for r in batch_rows]
    by_uid = {int(r["uid"]): r for r in batch_rows}
    try:
        mapping = with_backoff(
            lambda u=uids, d=dest_folder: client.move_uids(u, d)
        )
        moved = 0
        for uid in uids:
            row = by_uid[uid]
            dest_uid = mapping.get(uid)
            _record_move(conn, profile, row, dest_folder, dest_uid)
            moved += 1
        return moved, None
    except Exception as batch_err:
        if _is_conn_error(batch_err):
            return 0, batch_err
        moved = 0
        for uid in uids:
            row = by_uid[uid]
            try:
                dest_uid = with_backoff(
                    lambda u=uid, d=dest_folder: client.move_uid(u, d)
                )
                _record_move(conn, profile, row, dest_folder, dest_uid)
                moved += 1
            except Exception as e:
                if _is_conn_error(e):
                    return moved, e
                # Yahoo occasionally returns bare COPY/MOVE NO; one more shot often works.
                try:
                    time.sleep(1.5)
                    dest_uid = with_backoff(
                        lambda u=uid, d=dest_folder: client.move_uid(u, d)
                    )
                    _record_move(conn, profile, row, dest_folder, dest_uid)
                    moved += 1
                    continue
                except Exception as e2:
                    if _is_conn_error(e2):
                        return moved, e2
                    e = e2
                errors.append(
                    {
                        "folder": folder,
                        "uid": uid,
                        "error": str(e),
                        "batch_error": str(batch_err),
                    }
                )
                audit_log(
                    profile.audit_path,
                    "move_error",
                    account=profile.name,
                    folder=folder,
                    uid=uid,
                    error=str(e),
                    batch_error=str(batch_err),
                )
        return moved, None


def _apply_rows_to_folder(
    profile: Profile,
    rows: list[dict[str, Any]],
    dest_folder: str,
    *,
    preflight: dict[str, Any],
    progress_cb: Any | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    if limit is not None:
        rows = rows[:limit]
    if not rows:
        return {
            "moved": 0,
            "errors": [],
            "preflight": preflight,
            "move_batch_size": profile.move_batch_size,
            "reconnects": 0,
        }

    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    conn = init_db(profile.db_path)
    moved = 0
    errors: list[dict] = []
    batch_size = max(1, int(profile.move_batch_size))
    reconnects = 0

    def report(**kw: Any) -> None:
        if progress_cb:
            progress_cb(
                **{
                    **kw,
                    "moved_this_job": moved,
                    "errors_this_job": len(errors),
                    "batch_size": batch_size,
                    "reconnects": reconnects,
                }
            )

    def reconnect(folder: str) -> None:
        nonlocal client, reconnects
        try:
            client.close()
        except Exception:
            pass
        client = provider.connect(profile)
        client.ensure_folder(dest_folder)
        with_backoff(lambda f=folder: client.select(f, readonly=False))
        reconnects += 1
        report(folder=folder, last_error=f"reconnected (#{reconnects})")

    try:
        client.ensure_folder(dest_folder)
        report(phase="planned", total_planned=len(rows), remaining_estimate=len(rows))

        by_folder: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            by_folder[row["folder"]].append(row)

        for folder, folder_rows in by_folder.items():
            with_backoff(lambda f=folder: client.select(f, readonly=False))
            folder_rows.sort(key=lambda r: int(r["uid"]))
            report(
                folder=folder,
                phase="folder_start",
                remaining_in_folder=len(folder_rows),
                total_planned=len(rows),
                remaining_estimate=len(rows) - moved,
            )
            i = 0
            while i < len(folder_rows):
                batch_rows = folder_rows[i : i + batch_size]
                report(
                    folder=folder,
                    phase="batch",
                    batch_uids=len(batch_rows),
                    folder_index=i,
                    folder_total=len(folder_rows),
                    total_planned=len(rows),
                    remaining_estimate=len(rows) - moved,
                )
                n, conn_err = _move_batch(
                    client, profile, conn, folder, batch_rows, dest_folder, errors
                )
                if n:
                    moved += n
                    conn.commit()
                    report(folder=folder, last_ok_at=_now(), last_error=None)

                if conn_err is None:
                    i += len(batch_rows)
                    continue

                report(folder=folder, last_error=str(conn_err))
                if batch_size > 25:
                    batch_size = max(25, batch_size // 2)
                i += n
                try:
                    reconnect(folder)
                except Exception as re_err:
                    raise RuntimeError(
                        f"IMAP reconnect failed after {conn_err}: {re_err}"
                    ) from re_err

                remaining = folder_rows[i : i + batch_size]
                if not remaining:
                    continue
                n2, conn_err2 = _move_batch(
                    client, profile, conn, folder, remaining, dest_folder, errors
                )
                if n2:
                    moved += n2
                    i += n2
                    conn.commit()
                    report(folder=folder, last_ok_at=_now(), last_error=None)
                if conn_err2 is None:
                    i += len(remaining) - n2
                    continue

                bad = folder_rows[i]
                errors.append(
                    {
                        "folder": folder,
                        "uid": int(bad["uid"]),
                        "error": str(conn_err2),
                        "skipped_after_reconnect": True,
                    }
                )
                audit_log(
                    profile.audit_path,
                    "move_error",
                    account=profile.name,
                    folder=folder,
                    uid=int(bad["uid"]),
                    error=str(conn_err2),
                    skipped_after_reconnect=True,
                )
                i += 1
                try:
                    reconnect(folder)
                except Exception:
                    pass
                report(folder=folder, last_error=str(conn_err2))
    finally:
        try:
            client.close()
        except Exception:
            pass
        conn.close()

    return {
        "moved": moved,
        "errors": errors,
        "preflight": preflight,
        "move_batch_size": batch_size,
        "reconnects": reconnects,
    }


def apply_to_ready(
    profile: Profile,
    confirm: str,
    limit: int | None = None,
    progress_cb: Any | None = None,
) -> dict[str, Any]:
    if confirm.strip() != CONFIRM_READY:
        raise ValueError(
            f"Refusing apply: type exactly {CONFIRM_READY!r} to confirm. Got {confirm!r}."
        )
    preflight = preflight_staged(profile)
    if preflight["count"] == 0:
        return {"moved": 0, "errors": [], "preflight": preflight}

    conn = init_db(profile.db_path)
    try:
        sql = """
            SELECT s.folder, s.uid, s.rule_id, s.reason,
                   m.message_id, m.from_addr, m.subject, m.date_ts, m.size
            FROM staged s
            JOIN messages m ON m.folder = s.folder AND m.uid = s.uid
            WHERE s.included = 1
            ORDER BY s.folder, s.uid
        """
        rows = [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()

    return _apply_rows_to_folder(
        profile,
        rows,
        profile.ready_folder,
        preflight=preflight,
        progress_cb=progress_cb,
        limit=limit,
    )


def apply_to_kept(
    profile: Profile,
    confirm: str,
    limit: int | None = None,
    progress_cb: Any | None = None,
) -> dict[str, Any]:
    if confirm.strip() != CONFIRM_KEPT:
        raise ValueError(
            f"Refusing apply: type exactly {CONFIRM_KEPT!r} to confirm. Got {confirm!r}."
        )
    preflight = preflight_kept_inbox(profile)
    if preflight["count"] == 0:
        return {"moved": 0, "errors": [], "preflight": preflight}

    if progress_cb:
        progress_cb(
            phase="loading_rows",
            folder=profile.inbox_folder,
            total_planned=preflight["count"],
            remaining_estimate=preflight["count"],
        )

    from mail_janitor.keeper import keep_inclusion_sql
    from mail_janitor.rules import load_rules

    ruleset = load_rules(profile.rules_path)
    now_ts = int(time.time())
    incl_sql, incl_params = keep_inclusion_sql(ruleset, now_ts)
    conn = init_db(profile.db_path)
    try:
        where = f"lower(folder) = lower(?) AND ({incl_sql})"
        params = [profile.inbox_folder] + incl_params
        rows = [
            dict(r)
            for r in conn.execute(
                f"""
                SELECT folder, uid, ? AS rule_id, ? AS reason,
                       message_id, from_addr, subject, date_ts, size
                FROM messages
                WHERE {where}
                ORDER BY folder, uid
                """,
                [KEEP_APPLY_RULE_ID, "Keep rule match"] + params,
            ).fetchall()
        ]
    finally:
        conn.close()

    return _apply_rows_to_folder(
        profile,
        rows,
        profile.kept_folder,
        preflight=preflight,
        progress_cb=progress_cb,
        limit=limit,
    )


def undo_from_ready(
    profile: Profile,
    confirm: str,
    move_ids: list[int] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    if confirm.strip() != CONFIRM_UNDO:
        raise ValueError(
            f"Refusing undo: type exactly {CONFIRM_UNDO!r} to confirm. Got {confirm!r}."
        )
    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    conn = init_db(profile.db_path)
    restored = 0
    errors: list[dict] = []
    batch_size = max(1, int(profile.move_batch_size))
    try:
        with_backoff(lambda: client.select(profile.ready_folder, readonly=False))
        sql = """
            SELECT id, source_folder, source_uid, dest_folder, dest_uid,
                   message_id, from_addr, subject, date_ts, size, rule_id
            FROM moves
            WHERE undone = 0 AND dest_folder = ?
        """
        params: list[Any] = [profile.ready_folder]
        if move_ids:
            placeholders = ",".join("?" for _ in move_ids)
            sql += f" AND id IN ({placeholders})"
            params.extend(move_ids)
        sql += " ORDER BY id ASC"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        if limit is not None:
            rows = rows[:limit]

        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row.get("dest_uid") is None:
                errors.append({"id": row["id"], "error": "missing dest_uid; undo manually"})
                continue
            by_source[row["source_folder"]].append(row)

        for source_folder, group in by_source.items():
            client.ensure_folder(source_folder)
            for batch_rows in _chunk_rows(group, batch_size):
                uids = [int(r["dest_uid"]) for r in batch_rows]
                by_uid = {int(r["dest_uid"]): r for r in batch_rows}
                try:
                    mapping = with_backoff(
                        lambda u=uids, f=source_folder: client.move_uids(u, f)
                    )
                    for uid in uids:
                        row = by_uid[uid]
                        new_uid = mapping.get(uid)
                        conn.execute("UPDATE moves SET undone = 1 WHERE id = ?", (row["id"],))
                        conn.execute(
                            "DELETE FROM messages WHERE folder = ? AND uid = ?",
                            (profile.ready_folder, uid),
                        )
                        audit_log(
                            profile.audit_path,
                            "undo",
                            account=profile.name,
                            move_id=row["id"],
                            from_folder=profile.ready_folder,
                            from_uid=uid,
                            to_folder=source_folder,
                            to_uid=new_uid,
                        )
                        restored += 1
                except Exception as batch_err:
                    for uid in uids:
                        row = by_uid[uid]
                        try:
                            new_uid = with_backoff(
                                lambda u=uid, f=source_folder: client.move_uid(u, f)
                            )
                            conn.execute(
                                "UPDATE moves SET undone = 1 WHERE id = ?", (row["id"],)
                            )
                            conn.execute(
                                "DELETE FROM messages WHERE folder = ? AND uid = ?",
                                (profile.ready_folder, uid),
                            )
                            audit_log(
                                profile.audit_path,
                                "undo",
                                account=profile.name,
                                move_id=row["id"],
                                from_folder=profile.ready_folder,
                                from_uid=uid,
                                to_folder=source_folder,
                                to_uid=new_uid,
                            )
                            restored += 1
                        except Exception as e:
                            errors.append(
                                {
                                    "id": row["id"],
                                    "error": str(e),
                                    "batch_error": str(batch_err),
                                }
                            )
                conn.commit()
    finally:
        client.close()
        conn.close()
    return {"restored": restored, "errors": errors, "move_batch_size": batch_size}


def undo_from_kept(
    profile: Profile,
    confirm: str,
    move_ids: list[int] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    if confirm.strip() != CONFIRM_UNDO_KEPT:
        raise ValueError(
            f"Refusing undo: type exactly {CONFIRM_UNDO_KEPT!r} to confirm. Got {confirm!r}."
        )
    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    conn = init_db(profile.db_path)
    restored = 0
    errors: list[dict] = []
    batch_size = max(1, int(profile.move_batch_size))
    dest = profile.kept_folder
    try:
        with_backoff(lambda: client.select(dest, readonly=False))
        sql = """
            SELECT id, source_folder, source_uid, dest_folder, dest_uid,
                   message_id, from_addr, subject, date_ts, size, rule_id
            FROM moves
            WHERE undone = 0 AND dest_folder = ?
        """
        params: list[Any] = [dest]
        if move_ids:
            placeholders = ",".join("?" for _ in move_ids)
            sql += f" AND id IN ({placeholders})"
            params.extend(move_ids)
        sql += " ORDER BY id ASC"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        if limit is not None:
            rows = rows[:limit]

        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row.get("dest_uid") is None:
                errors.append({"id": row["id"], "error": "missing dest_uid; undo manually"})
                continue
            by_source[row["source_folder"]].append(row)

        for source_folder, group in by_source.items():
            client.ensure_folder(source_folder)
            for batch_rows in _chunk_rows(group, batch_size):
                uids = [int(r["dest_uid"]) for r in batch_rows]
                by_uid = {int(r["dest_uid"]): r for r in batch_rows}
                try:
                    mapping = with_backoff(
                        lambda u=uids, f=source_folder: client.move_uids(u, f)
                    )
                    for uid in uids:
                        row = by_uid[uid]
                        new_uid = mapping.get(uid)
                        conn.execute("UPDATE moves SET undone = 1 WHERE id = ?", (row["id"],))
                        conn.execute(
                            "DELETE FROM messages WHERE folder = ? AND uid = ?",
                            (dest, uid),
                        )
                        audit_log(
                            profile.audit_path,
                            "undo_kept",
                            account=profile.name,
                            move_id=row["id"],
                            from_folder=dest,
                            from_uid=uid,
                            to_folder=source_folder,
                            to_uid=new_uid,
                        )
                        restored += 1
                except Exception as batch_err:
                    for uid in uids:
                        row = by_uid[uid]
                        try:
                            new_uid = with_backoff(
                                lambda u=uid, f=source_folder: client.move_uid(u, f)
                            )
                            conn.execute(
                                "UPDATE moves SET undone = 1 WHERE id = ?", (row["id"],)
                            )
                            conn.execute(
                                "DELETE FROM messages WHERE folder = ? AND uid = ?",
                                (dest, uid),
                            )
                            audit_log(
                                profile.audit_path,
                                "undo_kept",
                                account=profile.name,
                                move_id=row["id"],
                                from_folder=dest,
                                from_uid=uid,
                                to_folder=source_folder,
                                to_uid=new_uid,
                            )
                            restored += 1
                        except Exception as e:
                            errors.append(
                                {
                                    "id": row["id"],
                                    "error": str(e),
                                    "batch_error": str(batch_err),
                                }
                            )
                conn.commit()
    finally:
        client.close()
        conn.close()
    return {"restored": restored, "errors": errors, "move_batch_size": batch_size}


def ready_to_trash(profile: Profile, confirm: str, batch_size: int = 100) -> dict[str, Any]:
    if confirm.strip() != CONFIRM_TRASH:
        raise ValueError(
            f"Refusing trash: type exactly {CONFIRM_TRASH!r} to confirm. Got {confirm!r}."
        )
    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    conn = init_db(profile.db_path)
    moved = 0
    errors: list[dict] = []
    imap_batch = max(1, min(int(batch_size), int(profile.move_batch_size)))
    try:
        with_backoff(lambda: client.select(profile.ready_folder, readonly=False))
        rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, dest_uid, source_folder, message_id, from_addr, subject, date_ts, size, rule_id
                FROM moves
                WHERE undone = 0 AND dest_folder = ? AND dest_uid IS NOT NULL
                ORDER BY id ASC
                LIMIT ?
                """,
                (profile.ready_folder, batch_size),
            ).fetchall()
        ]
        for batch_rows in _chunk_rows(rows, imap_batch):
            uids = [int(r["dest_uid"]) for r in batch_rows]
            by_uid = {int(r["dest_uid"]): r for r in batch_rows}
            try:
                mapping = with_backoff(
                    lambda u=uids: client.move_uids(u, profile.trash_folder)
                )
                for uid in uids:
                    row = by_uid[uid]
                    trash_uid = mapping.get(uid)
                    conn.execute(
                        """
                        UPDATE moves
                        SET dest_folder = ?, dest_uid = ?, moved_at = ?
                        WHERE id = ?
                        """,
                        (profile.trash_folder, trash_uid, _now(), row["id"]),
                    )
                    conn.execute(
                        "DELETE FROM messages WHERE folder = ? AND uid = ?",
                        (profile.ready_folder, uid),
                    )
                    audit_log(
                        profile.audit_path,
                        "to_trash",
                        account=profile.name,
                        move_id=row["id"],
                        from_folder=profile.ready_folder,
                        from_uid=uid,
                        trash_folder=profile.trash_folder,
                        trash_uid=trash_uid,
                        warning="Yahoo Trash auto-empties after 7 days and cannot be changed.",
                    )
                    moved += 1
            except Exception as batch_err:
                for uid in uids:
                    row = by_uid[uid]
                    try:
                        trash_uid = with_backoff(
                            lambda u=uid: client.move_uid(u, profile.trash_folder)
                        )
                        conn.execute(
                            """
                            UPDATE moves
                            SET dest_folder = ?, dest_uid = ?, moved_at = ?
                            WHERE id = ?
                            """,
                            (profile.trash_folder, trash_uid, _now(), row["id"]),
                        )
                        conn.execute(
                            "DELETE FROM messages WHERE folder = ? AND uid = ?",
                            (profile.ready_folder, uid),
                        )
                        audit_log(
                            profile.audit_path,
                            "to_trash",
                            account=profile.name,
                            move_id=row["id"],
                            from_folder=profile.ready_folder,
                            from_uid=uid,
                            trash_folder=profile.trash_folder,
                            trash_uid=trash_uid,
                            warning="Yahoo Trash auto-empties after 7 days and cannot be changed.",
                        )
                        moved += 1
                    except Exception as e:
                        errors.append(
                            {
                                "id": row["id"],
                                "uid": uid,
                                "error": str(e),
                                "batch_error": str(batch_err),
                            }
                        )
            conn.commit()
    finally:
        client.close()
        conn.close()
    return {
        "moved_to_trash": moved,
        "errors": errors,
        "warning": (
            "Yahoo Trash is automatically emptied after 7 days. "
            "You cannot change this schedule. Recovery after purge is not guaranteed."
        ),
        "batch_size": batch_size,
        "move_batch_size": imap_batch,
    }


def _chunk_rows(rows: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [rows[i : i + size] for i in range(0, len(rows), size)]


def list_moves(profile: Profile, undone_only: bool = True, limit: int = 100) -> list[dict]:
    conn = init_db(profile.db_path)
    try:
        sql = "SELECT * FROM moves"
        if undone_only:
            sql += " WHERE undone = 0"
        sql += " ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in conn.execute(sql, (limit,)).fetchall()]
    finally:
        conn.close()

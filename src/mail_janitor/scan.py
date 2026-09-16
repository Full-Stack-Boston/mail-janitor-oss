"""Resumeable headers-only mailbox scan."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mail_janitor.audit import audit_log
from mail_janitor.config import Profile
from mail_janitor.db import get_scan_progress, init_db, set_scan_progress, upsert_message
from mail_janitor.providers import get_provider
from mail_janitor.providers.base import chunked, with_backoff


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_mailbox(
    profile: Profile,
    resume: bool = True,
    progress_cb: Any | None = None,
) -> dict:
    provider = get_provider(profile.provider)
    exclude = set(profile.exclude_folders) | set(provider.default_exclude_folders())
    exclude.add(profile.ready_folder)
    exclude.add(profile.kept_folder)

    conn = init_db(profile.db_path)
    client = provider.connect(profile)
    started = time.monotonic()
    stats = {
        "folders": 0,
        "messages_upserted": 0,
        "folders_skipped": [],
        "errors": [],
        "batch_fallbacks": 0,
        "reconnects": 0,
        "uids_planned": 0,
        "uids_done": 0,
    }

    def report(**kw: Any) -> None:
        if not progress_cb:
            return
        elapsed = max(0.001, time.monotonic() - started)
        done = int(stats["uids_done"])
        total = int(stats["uids_planned"]) or None
        rate = done / elapsed if done else 0.0
        remaining = max(0, (total or 0) - done) if total else None
        eta = int(remaining / rate) if rate > 0 and remaining is not None else None
        pct = round(100.0 * done / total, 1) if total else None
        progress_cb(
            messages_upserted=stats["messages_upserted"],
            uids_done=done,
            uids_planned=total,
            folders_done=stats["folders"],
            errors=len(stats["errors"]),
            reconnects=stats["reconnects"],
            batch_fallbacks=stats["batch_fallbacks"],
            elapsed_sec=int(elapsed),
            eta_sec=eta,
            pct=pct,
            rate_per_sec=round(rate, 2) if done else None,
            **kw,
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

    def reconnect(folder: str) -> None:
        nonlocal client
        try:
            client.close()
        except Exception:
            pass
        client = provider.connect(profile)
        with_backoff(lambda f=folder: client.select(f, readonly=True))
        stats["reconnects"] += 1

    def upsert_rows(folder: str, rows: list[dict[str, Any]]) -> int:
        n = 0
        for row in rows:
            upsert_message(
                conn,
                {
                    "folder": folder,
                    "uid": row["uid"],
                    "message_id": row.get("message_id") or "",
                    "from_addr": row.get("from_addr") or "",
                    "from_domain": row.get("from_domain") or "",
                    "subject": row.get("subject") or "",
                    "date_ts": row.get("date_ts"),
                    "date_raw": row.get("date_raw") or "",
                    "size": int(row.get("size") or 0),
                    "flags": row.get("flags") or "",
                    "list_unsubscribe": int(row.get("list_unsubscribe") or 0),
                    "has_attachment": row.get("has_attachment"),
                    "scanned_at": _now(),
                },
            )
            n += 1
        return n

    def fetch_batch(folder: str, batch: list[int]) -> list[dict[str, Any]]:
        """Fetch headers; on failure reconnect / fall back to per-UID so gaps stay small."""
        try:
            return with_backoff(lambda b=batch: client.fetch_headers(b))
        except Exception as batch_err:
            if _is_conn_error(batch_err):
                try:
                    reconnect(folder)
                    return with_backoff(lambda b=batch: client.fetch_headers(b))
                except Exception as e2:
                    batch_err = e2
            # Per-UID fallback (encoding poison pills, stubborn SSL, etc.)
            stats["batch_fallbacks"] += 1
            rows: list[dict[str, Any]] = []
            for uid in batch:
                try:
                    part = with_backoff(lambda u=uid: client.fetch_headers([u]))
                    rows.extend(part)
                except Exception as e:
                    if _is_conn_error(e):
                        try:
                            reconnect(folder)
                            part = with_backoff(lambda u=uid: client.fetch_headers([u]))
                            rows.extend(part)
                            continue
                        except Exception as e3:
                            e = e3
                    stats["errors"].append(
                        {"folder": folder, "error": str(e), "batch": [uid]}
                    )
            if not rows:
                stats["errors"].append(
                    {
                        "folder": folder,
                        "error": str(batch_err),
                        "batch": batch[:5],
                    }
                )
            return rows

    try:
        folders = client.list_folders()
        work: list[tuple[str, int | None, list[int]]] = []
        report(phase="listing_folders", folder="(planning)")
        for folder_info in folders:
            folder = folder_info.name
            if "Noselect" in folder_info.flags or "\\Noselect" in folder_info.flags:
                stats["folders_skipped"].append(folder)
                continue
            if folder in exclude:
                stats["folders_skipped"].append(folder)
                continue

            try:
                exists, uidvalidity = with_backoff(
                    lambda f=folder: client.select(f, readonly=True)
                )
            except Exception as e:
                stats["errors"].append({"folder": folder, "error": str(e)})
                continue

            last_uid, prev_validity = get_scan_progress(conn, folder)
            if not resume or (
                prev_validity is not None
                and uidvalidity is not None
                and prev_validity != uidvalidity
            ):
                last_uid = 0

            try:
                uids = with_backoff(lambda: client.uid_search_all_above(last_uid))
            except Exception as e:
                stats["errors"].append({"folder": folder, "error": str(e)})
                continue

            if exists == 0:
                uids = []
            report(
                phase="listing_folders",
                folder=folder,
                folders_seen=len(work) + 1,
            )
            work.append((folder, uidvalidity, uids))

        stats["uids_planned"] = sum(len(u) for _, _, u in work)
        report(
            phase="planned",
            folder="(starting)",
            folders_planned=len(work),
        )

        for folder, uidvalidity, uids in work:
            with_backoff(lambda f=folder: client.select(f, readonly=True))
            last_uid, _ = get_scan_progress(conn, folder)
            max_uid = last_uid
            folder_total = len(uids)
            folder_done = 0
            report(
                phase="folder_start",
                folder=folder,
                folder_uids=folder_total,
                folder_done=0,
                folders_planned=len(work),
            )
            for batch in chunked(uids, profile.scan_batch_size):
                rows = fetch_batch(folder, batch)
                # Count planned UIDs as done even if some failed — keeps ETA honest.
                stats["uids_done"] += len(batch)
                folder_done += len(batch)
                if rows:
                    n = upsert_rows(folder, rows)
                    stats["messages_upserted"] += n
                    for row in rows:
                        max_uid = max(max_uid, int(row["uid"]))
                    set_scan_progress(conn, folder, max_uid, uidvalidity, _now())
                    conn.commit()
                report(
                    phase="batch",
                    folder=folder,
                    folder_uids=folder_total,
                    folder_done=folder_done,
                    folders_planned=len(work),
                )

            stats["folders"] += 1
            audit_log(
                profile.audit_path,
                "scan_folder",
                account=profile.name,
                folder=folder,
                last_uid=max_uid,
                upserted=stats["messages_upserted"],
            )
            report(
                phase="folder_done",
                folder=folder,
                folders_planned=len(work),
            )
    finally:
        client.close()
        conn.commit()
        conn.close()

    audit_log(profile.audit_path, "scan_complete", account=profile.name, **stats)
    return stats


def backfill_list_unsubscribe(profile: Profile) -> dict:
    """Re-fetch full HEADER for indexed UIDs and repair list_unsubscribe flags.

    Yahoo IMAP omits List-Unsubscribe from HEADER.FIELDS, so older scans may have
    every row stuck at 0. This is lighter than a full rescan (HEADER only, no
    BODYSTRUCTURE) and only updates the list_unsubscribe column.

    Emits PROGRESS lines on stdout (and a status file) for live watching.
    Skips rows already flagged list_unsubscribe=1 so restarts resume cheaply.
    """
    provider = get_provider(profile.provider)
    exclude = set(profile.exclude_folders) | set(provider.default_exclude_folders())
    exclude.add(profile.ready_folder)
    exclude.add(profile.kept_folder)

    conn = init_db(profile.db_path)
    client = provider.connect(profile)
    started = time.monotonic()
    status_path = Path("/tmp/mail-janitor-backfill-lu.status")
    stats = {
        "folders": 0,
        "checked": 0,
        "updated_to_1": 0,
        "still_0": 0,
        "missing_on_server": 0,
        "skipped_already_1": 0,
        "errors": [],
    }

    def emit(msg: str) -> None:
        print(msg, flush=True)

    def write_status(**extra: Any) -> None:
        elapsed = max(0.001, time.monotonic() - started)
        checked = int(stats["checked"])
        total = int(extra.get("total") or 0)
        rate = checked / elapsed
        remaining = max(0, total - checked)
        # Avoid wild ETA until we have a meaningful sample.
        eta_s = int(remaining / rate) if rate > 0 and checked >= 50 and total else -1
        lines = [
            f"checked={checked}",
            f"total={total}",
            f"pct={((100.0 * checked / total) if total else 0):.1f}",
            f"lu_found={stats['updated_to_1']}",
            f"lu_absent={stats['still_0']}",
            f"missing={stats['missing_on_server']}",
            f"skipped_already_1={stats['skipped_already_1']}",
            f"rate_per_sec={rate:.1f}",
            f"elapsed_sec={int(elapsed)}",
            f"eta_sec={eta_s}",
            f"folder={extra.get('folder', '')}",
            f"folder_done={extra.get('folder_done', 0)}",
            f"folder_total={extra.get('folder_total', 0)}",
            f"errors={len(stats['errors'])}",
        ]
        try:
            status_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass
        emit(
            "PROGRESS "
            + " ".join(lines)
        )

    try:
        folders = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT folder FROM messages ORDER BY folder"
            ).fetchall()
        ]
        already = int(
            conn.execute(
                "SELECT count(*) FROM messages WHERE list_unsubscribe = 1"
            ).fetchone()[0]
        )
        pending = int(
            conn.execute(
                "SELECT count(*) FROM messages WHERE list_unsubscribe = 0"
            ).fetchone()[0]
        )
        stats["skipped_already_1"] = already
        total = pending
        emit(
            f"Backfill plan: {pending} pending (list_unsubscribe=0), "
            f"{already} already flagged — total index {pending + already}"
        )
        write_status(total=total, folder="(starting)", folder_done=0, folder_total=0)

        for folder in folders:
            if folder in exclude:
                continue
            try:
                with_backoff(lambda f=folder: client.select(f, readonly=True))
            except Exception as e:
                stats["errors"].append({"folder": folder, "error": str(e)})
                continue

            uids = [
                int(r[0])
                for r in conn.execute(
                    """
                    SELECT uid FROM messages
                    WHERE folder = ? AND list_unsubscribe = 0
                    ORDER BY uid
                    """,
                    (folder,),
                ).fetchall()
            ]
            if not uids:
                continue

            folder_total = len(uids)
            folder_done = 0
            emit(f"FOLDER start {folder!r} pending={folder_total}")

            for batch in chunked(uids, profile.scan_batch_size):
                try:
                    # HEADER only — see fetch_headers() note about Yahoo + List-Unsubscribe.
                    uid_set = ",".join(str(u) for u in batch)
                    typ, data = with_backoff(
                        lambda s=uid_set: client.imap.uid(
                            "fetch", s, "(UID BODY.PEEK[HEADER])"
                        )
                    )
                    if typ != "OK" or not data:
                        continue
                    rows = client._parse_fetch_headers(data)
                except Exception as e:
                    stats["errors"].append(
                        {"folder": folder, "error": str(e), "batch": batch[:5]}
                    )
                    write_status(
                        total=total,
                        folder=folder,
                        folder_done=folder_done,
                        folder_total=folder_total,
                    )
                    continue

                seen: set[int] = set()
                for row in rows:
                    uid = int(row["uid"])
                    seen.add(uid)
                    flag = int(row.get("list_unsubscribe") or 0)
                    stats["checked"] += 1
                    folder_done += 1
                    conn.execute(
                        "UPDATE messages SET list_unsubscribe = ? WHERE folder = ? AND uid = ?",
                        (flag, folder, uid),
                    )
                    if flag:
                        stats["updated_to_1"] += 1
                    else:
                        stats["still_0"] += 1
                missing = set(batch) - seen
                # Treat missing-on-server as checked (leave flag 0; nothing to fetch).
                for uid in missing:
                    stats["checked"] += 1
                    folder_done += 1
                    stats["missing_on_server"] += 1
                    stats["still_0"] += 1
                conn.commit()
                write_status(
                    total=total,
                    folder=folder,
                    folder_done=folder_done,
                    folder_total=folder_total,
                )

            stats["folders"] += 1
            emit(f"FOLDER done {folder!r}")
    finally:
        client.close()
        conn.commit()
        conn.close()

    audit_log(
        profile.audit_path, "backfill_list_unsubscribe", account=profile.name, **stats
    )
    emit(f"DONE {stats}")
    return stats


def blank_header_stats(profile: Profile) -> dict[str, Any]:
    """Count indexed rows missing From (scan poison pills)."""
    conn = init_db(profile.db_path)
    try:
        total = int(conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"])
        blank = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM messages WHERE from_addr IS NULL OR from_addr = ''"
            ).fetchone()["c"]
        )
    finally:
        conn.close()
    ratio = (blank / total) if total else 0.0
    return {
        "total": total,
        "blank": blank,
        "ratio": ratio,
        "needs_repair": blank > 0 and (blank >= 3 or ratio >= 0.01),
    }


def refresh_blank_headers(profile: Profile) -> dict[str, Any]:
    """Re-fetch headers for indexed rows missing From/Subject (scan poison pills).

    Older scans combined BODYSTRUCTURE + HEADER in one Yahoo FETCH; nested
    BODYSTRUCTURE literals could wipe header fields while SIZE remained. Open
    (full body) still worked. This repairs those blank index rows in place.
    """
    provider = get_provider(profile.provider)
    conn = init_db(profile.db_path)
    client = provider.connect(profile)
    stats: dict[str, Any] = {
        "blank_before": 0,
        "repaired": 0,
        "still_blank": 0,
        "missing_on_server": 0,
        "errors": [],
        "samples": [],
    }
    try:
        blanks = [
            dict(r)
            for r in conn.execute(
                """
                SELECT folder, uid FROM messages
                WHERE from_addr IS NULL OR from_addr = ''
                ORDER BY folder, uid
                """
            ).fetchall()
        ]
        stats["blank_before"] = len(blanks)
        by_folder: dict[str, list[int]] = {}
        for row in blanks:
            by_folder.setdefault(str(row["folder"]), []).append(int(row["uid"]))

        for folder, uids in by_folder.items():
            try:
                with_backoff(lambda f=folder: client.select(f, readonly=True))
            except Exception as e:
                stats["errors"].append({"folder": folder, "error": str(e)})
                continue
            for batch in chunked(uids, profile.scan_batch_size):
                try:
                    rows = with_backoff(lambda b=batch: client.fetch_headers(b))
                except Exception as e:
                    stats["errors"].append(
                        {"folder": folder, "error": str(e), "batch": batch[:5]}
                    )
                    continue
                got = {int(r["uid"]): r for r in rows}
                for uid in batch:
                    row = got.get(uid)
                    if row is None:
                        stats["missing_on_server"] += 1
                        continue
                    if not (row.get("from_addr") or row.get("subject")):
                        stats["still_blank"] += 1
                        continue
                    upsert_message(
                        conn,
                        {
                            "folder": folder,
                            "uid": uid,
                            "message_id": row.get("message_id") or "",
                            "from_addr": row.get("from_addr") or "",
                            "from_domain": row.get("from_domain") or "",
                            "subject": row.get("subject") or "",
                            "date_ts": row.get("date_ts"),
                            "date_raw": row.get("date_raw") or "",
                            "size": int(row.get("size") or 0),
                            "flags": row.get("flags") or "",
                            "list_unsubscribe": int(row.get("list_unsubscribe") or 0),
                            "has_attachment": row.get("has_attachment"),
                            "scanned_at": _now(),
                        },
                    )
                    stats["repaired"] += 1
                    if len(stats["samples"]) < 8:
                        stats["samples"].append(
                            {
                                "folder": folder,
                                "uid": uid,
                                "from_addr": row.get("from_addr"),
                                "subject": (row.get("subject") or "")[:80],
                            }
                        )
                conn.commit()
    finally:
        client.close()
        conn.commit()
        conn.close()

    audit_log(profile.audit_path, "refresh_blank_headers", account=profile.name, **stats)
    return stats

"""SQLite header index — no message bodies stored."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    message_id TEXT,
    from_addr TEXT,
    from_domain TEXT,
    subject TEXT,
    date_ts INTEGER,
    date_raw TEXT,
    size INTEGER DEFAULT 0,
    flags TEXT,
    list_unsubscribe INTEGER DEFAULT 0,
    has_attachment INTEGER,
    scanned_at TEXT,
    PRIMARY KEY (folder, uid)
);

CREATE INDEX IF NOT EXISTS idx_messages_from_domain ON messages(from_domain);
CREATE INDEX IF NOT EXISTS idx_messages_from_addr ON messages(from_addr);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date_ts);
CREATE INDEX IF NOT EXISTS idx_messages_size ON messages(size);
CREATE INDEX IF NOT EXISTS idx_messages_list_unsub ON messages(list_unsubscribe);

CREATE TABLE IF NOT EXISTS scan_progress (
    folder TEXT PRIMARY KEY,
    last_uid INTEGER NOT NULL DEFAULT 0,
    uidvalidity INTEGER,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS staged (
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    reason TEXT,
    included INTEGER NOT NULL DEFAULT 1,
    staged_at TEXT,
    PRIMARY KEY (folder, uid)
);

CREATE INDEX IF NOT EXISTS idx_staged_included ON staged(included);

CREATE TABLE IF NOT EXISTS moves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_folder TEXT NOT NULL,
    source_uid INTEGER NOT NULL,
    dest_folder TEXT NOT NULL,
    dest_uid INTEGER,
    message_id TEXT,
    from_addr TEXT,
    subject TEXT,
    date_ts INTEGER,
    size INTEGER,
    rule_id TEXT,
    moved_at TEXT NOT NULL,
    undone INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_moves_undone ON moves(undone);
CREATE INDEX IF NOT EXISTS idx_moves_dest ON moves(dest_folder, dest_uid);

CREATE TABLE IF NOT EXISTS firewall_state (
    watch_folder TEXT PRIMARY KEY,
    last_uid INTEGER NOT NULL DEFAULT 0,
    uidvalidity INTEGER,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    reason TEXT,
    rule_id TEXT,
    source_folder TEXT NOT NULL,
    source_uid INTEGER NOT NULL,
    dest_folder TEXT,
    dest_uid INTEGER,
    message_id TEXT,
    from_addr TEXT,
    from_domain TEXT,
    subject TEXT,
    date_ts INTEGER,
    size INTEGER,
    created_at TEXT NOT NULL,
    released INTEGER NOT NULL DEFAULT 0,
    released_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_firewall_actions_released ON firewall_actions(released);
CREATE INDEX IF NOT EXISTS idx_firewall_actions_dest ON firewall_actions(dest_folder, dest_uid);

CREATE TABLE IF NOT EXISTS keeper_seen (
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    seen_at TEXT,
    PRIMARY KEY (folder, uid)
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
    if "has_attachment" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN has_attachment INTEGER")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_has_attachment ON messages(has_attachment)"
    )
    # Older DBs created before firewall tables
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS firewall_state (
            watch_folder TEXT PRIMARY KEY,
            last_uid INTEGER NOT NULL DEFAULT 0,
            uidvalidity INTEGER,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS firewall_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            reason TEXT,
            rule_id TEXT,
            source_folder TEXT NOT NULL,
            source_uid INTEGER NOT NULL,
            dest_folder TEXT,
            dest_uid INTEGER,
            message_id TEXT,
            from_addr TEXT,
            from_domain TEXT,
            subject TEXT,
            date_ts INTEGER,
            size INTEGER,
            created_at TEXT NOT NULL,
            released INTEGER NOT NULL DEFAULT 0,
            released_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_firewall_actions_released ON firewall_actions(released);
        CREATE INDEX IF NOT EXISTS idx_firewall_actions_dest ON firewall_actions(dest_folder, dest_uid);
        """
    )


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = connect(db_path)
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


@contextmanager
def db_session(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = init_db(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_message(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    payload = {
        "folder": row["folder"],
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
        "scanned_at": row.get("scanned_at") or "",
    }
    conn.execute(
        """
        INSERT INTO messages (
            folder, uid, message_id, from_addr, from_domain, subject,
            date_ts, date_raw, size, flags, list_unsubscribe, has_attachment, scanned_at
        ) VALUES (
            :folder, :uid, :message_id, :from_addr, :from_domain, :subject,
            :date_ts, :date_raw, :size, :flags, :list_unsubscribe, :has_attachment, :scanned_at
        )
        ON CONFLICT(folder, uid) DO UPDATE SET
            message_id=excluded.message_id,
            from_addr=excluded.from_addr,
            from_domain=excluded.from_domain,
            subject=excluded.subject,
            date_ts=excluded.date_ts,
            date_raw=excluded.date_raw,
            size=excluded.size,
            flags=excluded.flags,
            list_unsubscribe=excluded.list_unsubscribe,
            has_attachment=COALESCE(excluded.has_attachment, messages.has_attachment),
            scanned_at=excluded.scanned_at
        """,
        payload,
    )


def get_scan_progress(conn: sqlite3.Connection, folder: str) -> tuple[int, int | None]:
    cur = conn.execute(
        "SELECT last_uid, uidvalidity FROM scan_progress WHERE folder = ?",
        (folder,),
    )
    row = cur.fetchone()
    if not row:
        return 0, None
    return int(row["last_uid"]), row["uidvalidity"]


def set_scan_progress(
    conn: sqlite3.Connection,
    folder: str,
    last_uid: int,
    uidvalidity: int | None,
    updated_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO scan_progress (folder, last_uid, uidvalidity, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(folder) DO UPDATE SET
            last_uid=excluded.last_uid,
            uidvalidity=excluded.uidvalidity,
            updated_at=excluded.updated_at
        """,
        (folder, last_uid, uidvalidity, updated_at),
    )


def message_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"])


def list_indexed_folders(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Distinct folders in the local index with message counts."""
    return [
        {"folder": row["folder"], "count": int(row["c"])}
        for row in conn.execute(
            """
            SELECT folder, COUNT(*) AS c
            FROM messages
            GROUP BY folder
            ORDER BY c DESC, folder ASC
            """
        ).fetchall()
    ]


def folder_message_count(conn: sqlite3.Connection, folder: str) -> int:
    """Messages indexed under a folder (case-insensitive name)."""
    return int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM messages WHERE lower(folder) = lower(?)",
            (folder,),
        ).fetchone()["c"]
    )


def inbox_message_count(conn: sqlite3.Connection, inbox_folder: str = "Inbox") -> int:
    """Messages still indexed under the triage inbox (drops as apply moves them)."""
    return folder_message_count(conn, inbox_folder)


def staged_count(conn: sqlite3.Connection, included_only: bool = True) -> int:
    if included_only:
        return int(
            conn.execute("SELECT COUNT(*) AS c FROM staged WHERE included = 1").fetchone()["c"]
        )
    return int(conn.execute("SELECT COUNT(*) AS c FROM staged").fetchone()["c"])

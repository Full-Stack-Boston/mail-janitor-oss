from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mail_janitor.config import Profile
from mail_janitor.db import init_db, upsert_message
from mail_janitor.providers.base import FolderInfo, ImapClient


@pytest.fixture
def profile(tmp_path: Path) -> Profile:
    (tmp_path / "rules.yaml").write_text("keep: []\nstage: []\n")
    (tmp_path / "firewall.yaml").write_text(
        "enabled: true\nwatch_folder: Inbox\nquarantine_folder: Quarantine\n"
        "poll_seconds: 0\nheuristic_quarantine: true\nallow: []\n"
        "block:\n  - id: blocked\n    from_domain: bad.test\n    action: stage\n"
    )
    return Profile(
        name="p",
        path=tmp_path,
        provider="imap",
        email="e@x",
        imap_host="h",
        imap_port=993,
        imap_ssl=True,
        app_password="pw",
        scan_batch_size=2,
        move_batch_size=2,
    )


def add_message(profile, uid=1, folder="Inbox", sender="a@x", domain="x"):
    c = init_db(profile.db_path)
    upsert_message(
        c,
        {
            "folder": folder,
            "uid": uid,
            "message_id": f"m{uid}",
            "from_addr": sender,
            "from_domain": domain,
            "subject": f"s{uid}",
            "date_ts": 100,
            "size": 20,
        },
    )
    c.commit()
    c.close()


class Client:
    def __init__(self):
        self.closed = False
        self.moves = []
        self.move_many_error = None
        self.move_one_error = None
        self.folders = [FolderInfo("Inbox", ""), FolderInfo("Skip", "\\Noselect")]
        self.search = [1, 2]
        self.headers = [
            {
                "uid": 1,
                "message_id": "m1",
                "from_addr": "a@x",
                "from_domain": "x",
                "subject": "one",
                "date_ts": 100,
                "size": 10,
            },
            {
                "uid": 2,
                "message_id": "m2",
                "from_addr": "b@bad.test",
                "from_domain": "bad.test",
                "subject": "two",
                "date_ts": 101,
                "size": 20,
            },
        ]
        self.imap = SimpleNamespace(uid=lambda *a: ("OK", []))

    def close(self):
        self.closed = True

    def ensure_folder(self, f):
        pass

    def select(self, f, readonly=True):
        return 2, 10

    def list_folders(self):
        return self.folders

    def uid_search_all_above(self, last):
        return [u for u in self.search if u > last]

    def fetch_headers(self, uids):
        return [r for r in self.headers if r["uid"] in uids]

    def _parse_fetch_headers(self, data):
        return ImapClient("h", 1, "e", "p")._parse_fetch_headers(data)

    def move_uids(self, uids, folder):
        if self.move_many_error:
            raise self.move_many_error
        self.moves.append((list(uids), folder))
        return {u: u + 100 for u in uids}

    def move_uid(self, uid, folder):
        if self.move_one_error:
            raise self.move_one_error
        self.moves.append((uid, folder))
        return uid + 100


def provider_for(client):
    return SimpleNamespace(
        connect=lambda p: client,
        default_exclude_folders=lambda: ["Excluded"],
    )


def test_apply_preflight_record_and_success(profile, monkeypatch):
    import mail_janitor.apply as apply

    add_message(profile, 1)
    c = init_db(profile.db_path)
    c.execute(
        "INSERT INTO staged(folder,uid,rule_id,reason,included) VALUES(?,?,?,?,1)",
        ("Inbox", 1, "r", "why"),
    )
    c.commit()
    c.close()
    assert apply.preflight_staged(profile, detail=False)["count"] == 1
    detail = apply.preflight_staged(profile)
    assert detail["by_rule"][0]["rule_id"] == "r" and detail["top_senders"]

    client = Client()
    monkeypatch.setattr(apply, "get_provider", lambda n: provider_for(client))
    progress = []
    out = apply.apply_to_ready(
        profile, apply.CONFIRM_READY, progress_cb=lambda **k: progress.append(k)
    )
    assert out["moved"] == 1 and progress and client.closed
    assert apply.list_moves(profile)[0]["dest_uid"] == 101
    assert len(apply.list_moves(profile, undone_only=False)) == 1
    with pytest.raises(ValueError):
        apply.apply_to_ready(profile, "bad")
    assert apply.apply_to_ready(profile, apply.CONFIRM_READY)["moved"] == 0


def test_apply_kept_preflight_and_success(profile, monkeypatch):
    import mail_janitor.apply as apply

    profile.rules_path.write_text(
        "keep:\n- id: k\n  from_address: a@x\nstage: []\n"
    )
    add_message(profile, 1)
    assert apply.preflight_kept_inbox(profile, detail=False)["count"] == 1
    assert apply.preflight_kept_inbox(profile)["top_senders"]
    client = Client()
    monkeypatch.setattr(apply, "get_provider", lambda n: provider_for(client))
    events = []
    out = apply.apply_to_kept(
        profile,
        apply.CONFIRM_KEPT,
        limit=1,
        progress_cb=lambda **k: events.append(k),
    )
    assert out["moved"] == 1 and events
    with pytest.raises(ValueError):
        apply.apply_to_kept(profile, "bad")
    assert apply.apply_to_kept(profile, apply.CONFIRM_KEPT)["moved"] == 0
    profile.rules_path.write_text("keep: []\nstage: []\n")
    assert apply.preflight_kept_inbox(profile)["count"] == 0
    assert apply._apply_rows_to_folder(
        profile, [{"folder": "Inbox", "uid": 1}], "D", preflight={}, limit=0
    )["moved"] == 0


def test_apply_move_batch_fallbacks(profile, monkeypatch):
    import mail_janitor.apply as apply

    row = {
        "folder": "Inbox",
        "uid": 1,
        "message_id": "m",
        "from_addr": "a@x",
        "subject": "s",
        "date_ts": 1,
        "size": 2,
        "rule_id": "r",
    }
    add_message(profile)
    conn = init_db(profile.db_path)
    client = Client()
    client.move_many_error = ValueError("NO")
    errors = []
    monkeypatch.setattr(apply.time, "sleep", lambda n: None)
    n, err = apply._move_batch(client, profile, conn, "Inbox", [row], "D", errors)
    assert (n, err) == (1, None)

    conn.commit()
    add_message(profile)
    client.move_one_error = ValueError("also NO")
    n, err = apply._move_batch(client, profile, conn, "Inbox", [row], "D", errors)
    assert n == 0 and err is None and errors

    client.move_many_error = OSError("connection reset")
    n, err = apply._move_batch(client, profile, conn, "Inbox", [row], "D", [])
    assert n == 0 and err
    client.move_many_error = ValueError("NO")
    client.move_one_error = OSError("connection reset")
    n, err = apply._move_batch(client, profile, conn, "Inbox", [row], "D", [])
    assert n == 0 and err

    attempts = {"n": 0}

    def retry_once(uid, folder):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ValueError("NO")
        return 10

    client.move_one_error = None
    client.move_uid = retry_once
    add_message(profile)
    n, err = apply._move_batch(client, profile, conn, "Inbox", [row], "D", [])
    assert n == 1 and err is None
    attempts["n"] = 0

    def retry_connection(uid, folder):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ValueError("NO")
        raise OSError("connection reset")

    client.move_uid = retry_connection
    n, err = apply._move_batch(client, profile, conn, "Inbox", [row], "D", [])
    assert n == 0 and err
    assert apply._is_conn_error(OSError("SSL EOF"))
    assert not apply._is_conn_error(ValueError("no"))
    conn.close()


def test_apply_reconnect_and_error_paths(profile, monkeypatch):
    import mail_janitor.apply as apply

    rows = []
    for uid in range(1, 4):
        add_message(profile, uid)
        rows.append({"folder": "Inbox", "uid": uid})
    clients = [Client(), Client(), Client()]
    provider = SimpleNamespace(connect=lambda p: clients.pop(0))
    monkeypatch.setattr(apply, "get_provider", lambda n: provider)
    sequence = iter([(1, OSError("connection")), (1, None), (1, OSError("reset")), (0, OSError("reset"))])
    monkeypatch.setattr(apply, "_move_batch", lambda *a, **k: next(sequence))
    out = apply._apply_rows_to_folder(
        profile, rows, "D", preflight={}, progress_cb=lambda **k: None
    )
    assert out["moved"] >= 2 and out["reconnects"] >= 1
    assert apply._apply_rows_to_folder(profile, [], "D", preflight={})["moved"] == 0

    # Reconnect itself fails.
    first = Client()
    provider = SimpleNamespace(
        connect=lambda p: first
        if not first.closed
        else (_ for _ in ()).throw(OSError("reconnect failed"))
    )
    monkeypatch.setattr(apply, "get_provider", lambda n: provider)
    monkeypatch.setattr(apply, "_move_batch", lambda *a, **k: (0, OSError("connection")))
    with pytest.raises(RuntimeError, match="reconnect"):
        apply._apply_rows_to_folder(profile, [rows[0]], "D", preflight={})

    # Large batch shrinks; persistent post-reconnect error skips one UID.
    profile.move_batch_size = 100
    clients = [Client(), Client(), Client()]
    monkeypatch.setattr(
        apply,
        "get_provider",
        lambda n: SimpleNamespace(connect=lambda p: clients.pop(0)),
    )
    seq = iter(
        [
            (0, OSError("connection")),
            (0, OSError("connection")),
            (1, None),
        ]
    )
    monkeypatch.setattr(apply, "_move_batch", lambda *a, **k: next(seq))
    out = apply._apply_rows_to_folder(
        profile, rows[:2], "D", preflight={}, progress_cb=lambda **k: None
    )
    assert out["errors"] and out["move_batch_size"] == 50

    # A fully moved batch can still report a connection error; no retry remains.
    clients = [Client(), Client()]
    monkeypatch.setattr(
        apply,
        "get_provider",
        lambda n: SimpleNamespace(connect=lambda p: clients.pop(0)),
    )
    monkeypatch.setattr(apply, "_move_batch", lambda *a, **k: (1, OSError("reset")))
    assert apply._apply_rows_to_folder(
        profile, rows[:1], "D", preflight={}
    )["moved"] == 1

    # Best-effort closes on reconnect/finalization.
    class BadClose(Client):
        def close(self):
            raise ValueError("close")

    clients = [BadClose(), BadClose()]
    monkeypatch.setattr(
        apply,
        "get_provider",
        lambda n: SimpleNamespace(connect=lambda p: clients.pop(0)),
    )
    seq = iter([(0, OSError("reset")), (0, OSError("reset"))])
    monkeypatch.setattr(apply, "_move_batch", lambda *a, **k: next(seq))
    apply._apply_rows_to_folder(profile, rows[:1], "D", preflight={})


def _insert_move(profile, dest="ready2delete", uid=101, source="Inbox"):
    c = init_db(profile.db_path)
    c.execute(
        """INSERT INTO moves(source_folder,source_uid,dest_folder,dest_uid,moved_at)
           VALUES(?,?,?,?,?)""",
        (source, uid - 100, dest, uid, "now"),
    )
    c.commit()
    mid = c.execute("SELECT max(id) FROM moves").fetchone()[0]
    c.close()
    return mid


def test_apply_undo_kept_and_trash(profile, monkeypatch):
    import mail_janitor.apply as apply

    client = Client()
    monkeypatch.setattr(apply, "get_provider", lambda n: provider_for(client))
    with pytest.raises(ValueError):
        apply.undo_from_ready(profile, "bad")
    missing = _insert_move(profile, uid=100)
    c = init_db(profile.db_path)
    c.execute("UPDATE moves SET dest_uid=NULL WHERE id=?", (missing,))
    c.commit()
    c.close()
    assert apply.undo_from_ready(profile, apply.CONFIRM_UNDO)["errors"]

    mid = _insert_move(profile)
    out = apply.undo_from_ready(
        profile, apply.CONFIRM_UNDO, move_ids=[mid], limit=1
    )
    assert out["restored"] == 1

    mid = _insert_move(profile, dest=profile.kept_folder)
    with pytest.raises(ValueError):
        apply.undo_from_kept(profile, "bad")
    assert apply.undo_from_kept(
        profile, apply.CONFIRM_UNDO_KEPT, move_ids=[mid], limit=1
    )["restored"] == 1
    missing = _insert_move(profile, dest=profile.kept_folder)
    c = init_db(profile.db_path)
    c.execute("UPDATE moves SET dest_uid=NULL WHERE id=?", (missing,))
    c.commit()
    c.close()
    assert apply.undo_from_kept(profile, apply.CONFIRM_UNDO_KEPT)["errors"]

    mid = _insert_move(profile)
    with pytest.raises(ValueError):
        apply.ready_to_trash(profile, "bad")
    out = apply.ready_to_trash(profile, apply.CONFIRM_TRASH, batch_size=1)
    assert out["moved_to_trash"] == 1
    assert apply._chunk_rows([{"x": 1}, {"x": 2}], 1) == [
        [{"x": 1}],
        [{"x": 2}],
    ]


def test_apply_undo_and_trash_fallback_errors(profile, monkeypatch):
    import mail_janitor.apply as apply

    client = Client()
    client.move_many_error = ValueError("batch")
    monkeypatch.setattr(apply, "get_provider", lambda n: provider_for(client))
    _insert_move(profile)
    assert apply.undo_from_ready(profile, apply.CONFIRM_UNDO)["restored"] == 1
    _insert_move(profile, dest=profile.kept_folder)
    assert apply.undo_from_kept(profile, apply.CONFIRM_UNDO_KEPT)["restored"] == 1
    _insert_move(profile)
    assert apply.ready_to_trash(profile, apply.CONFIRM_TRASH)["moved_to_trash"] == 1

    client.move_one_error = ValueError("one")
    _insert_move(profile)
    assert apply.undo_from_ready(profile, apply.CONFIRM_UNDO)["errors"]
    _insert_move(profile, dest=profile.kept_folder)
    assert apply.undo_from_kept(profile, apply.CONFIRM_UNDO_KEPT)["errors"]
    _insert_move(profile)
    assert apply.ready_to_trash(profile, apply.CONFIRM_TRASH)["errors"]


def test_firewall_status_process_watch_release(profile, monkeypatch):
    import mail_janitor.firewall as fw

    client = Client()
    monkeypatch.setattr(fw, "get_provider", lambda n: provider_for(client))
    status = fw.firewall_status(profile)
    assert status["enabled"] and status["last_uid"] == 0
    c = init_db(profile.db_path)
    assert fw.get_firewall_progress(c, "Inbox") == (0, None)
    fw.set_firewall_progress(c, "Inbox", 0, 10)
    c.commit()
    c.close()

    # First pass initializes without touching backlog.
    init = fw.process_once(profile)
    assert init["initialized"]
    client.search = [3, 4]
    client.headers = [
        {**client.headers[0], "uid": 3},
        {**client.headers[1], "uid": 4},
    ]
    out = fw.process_once(profile)
    assert out["seen"] == 2 and out["passed"] == 1 and out["quarantined"] == 1
    assert fw.list_quarantine(profile)
    assert fw.release_quarantine(profile, action_ids=[1], limit=1)["restored"] == 1
    assert fw.watch_loop(profile, once=True)["ok"]
    assert fw.watch_loop(profile, max_iterations=1, dry_run=True)["ok"]


def test_firewall_disabled_empty_dryrun_and_errors(profile, monkeypatch):
    import mail_janitor.firewall as fw

    profile.firewall_path.write_text("enabled: false\n")
    assert fw.process_once(profile)["ok"] is False
    profile.firewall_path.write_text(
        "enabled: true\nwatch_folder: Inbox\nquarantine_folder: Q\n"
        "heuristic_quarantine: true\nblock:\n- id: b\n  from_domain: bad.test\n"
    )
    client = Client()
    client.search = []
    monkeypatch.setattr(fw, "get_provider", lambda n: provider_for(client))
    assert fw.process_once(profile)["seen"] == 0
    c = init_db(profile.db_path)
    fw.set_firewall_progress(c, "Inbox", 1, 10)
    c.commit()
    c.close()
    client.search = [2]
    client.headers = [{**client.headers[1], "uid": 2}]
    assert fw.process_once(profile, dry_run=True)["quarantined"] == 1

    client.move_one_error = ValueError("move")
    assert fw.process_once(profile)["errors"]
    # Release error branch.
    c = init_db(profile.db_path)
    c.execute(
        """INSERT INTO firewall_actions(action,source_folder,source_uid,dest_uid,created_at,released)
           VALUES('quarantine','Inbox',9,109,'now',0)"""
    )
    c.commit()
    c.close()
    assert fw.release_quarantine(profile)["errors"]


def test_firewall_watermark_empty_missing_and_sleep(profile, monkeypatch):
    import mail_janitor.firewall as fw

    client = Client()
    monkeypatch.setattr(fw, "get_provider", lambda n: provider_for(client))
    c = init_db(profile.db_path)
    fw.set_firewall_progress(c, "Inbox", 1, 999)
    c.commit()
    c.close()
    assert fw.process_once(profile)["initialized"]

    # Empty mailbox and missing FETCH row.
    client.select = lambda *a, **k: (0, 10)
    assert fw.process_once(profile)["seen"] == 0
    client.select = lambda *a, **k: (2, 10)
    c = init_db(profile.db_path)
    fw.set_firewall_progress(c, "Inbox", 1, 10)
    c.commit()
    c.close()
    client.search = [2]
    client.headers = []
    assert fw.process_once(profile)["seen"] == 0
    monkeypatch.setattr(fw.time, "sleep", lambda n: None)
    assert fw.watch_loop(profile, max_iterations=2)["ok"]


def test_scan_happy_resume_excludes_and_callbacks(profile, monkeypatch):
    import mail_janitor.scan as scan

    client = Client()
    client.folders.extend(
        [FolderInfo("Excluded", ""), FolderInfo(profile.ready_folder, "")]
    )
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    events = []
    out = scan.scan_mailbox(profile, progress_cb=lambda **k: events.append(k))
    assert out["messages_upserted"] == 2 and events
    assert {"Skip", "Excluded", profile.ready_folder} <= set(out["folders_skipped"])
    # Resume finds no newer UIDs; no-resume resets progress.
    assert scan.scan_mailbox(profile)["messages_upserted"] == 0
    assert scan.scan_mailbox(profile, resume=False)["messages_upserted"] == 2


def test_scan_errors_fallback_reconnect(profile, monkeypatch):
    import mail_janitor.scan as scan

    client = Client()
    attempts = {"fetch": 0}

    def fetch(uids):
        attempts["fetch"] += 1
        if len(uids) > 1:
            raise ValueError("poison")
        if uids == [1]:
            return [client.headers[0]]
        raise ValueError("bad single")

    client.fetch_headers = fetch
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    monkeypatch.setattr(scan, "with_backoff", lambda fn: fn())
    out = scan.scan_mailbox(profile, resume=False)
    assert out["batch_fallbacks"] == 1 and out["errors"]

    # Planning select/search failures.
    client = Client()
    client.select = lambda *a, **k: (_ for _ in ()).throw(ValueError("select"))
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    assert scan.scan_mailbox(profile)["errors"]


def test_scan_connection_recovery_and_empty_rows(profile, monkeypatch):
    import mail_janitor.scan as scan

    first, second = Client(), Client()
    first.fetch_headers = lambda u: (_ for _ in ()).throw(OSError("connection reset"))
    first.close = lambda: (_ for _ in ()).throw(ValueError("close"))
    second.fetch_headers = lambda u: [r for r in second.headers if r["uid"] in u]
    clients = [first, second]
    monkeypatch.setattr(
        scan,
        "get_provider",
        lambda n: SimpleNamespace(
            connect=lambda p: clients.pop(0),
            default_exclude_folders=lambda: [],
        ),
    )
    monkeypatch.setattr(scan, "with_backoff", lambda fn: fn())
    out = scan.scan_mailbox(profile)
    assert out["reconnects"] == 1 and out["messages_upserted"] == 2

    # Connection failure after reconnect falls through per-UID, then records no rows.
    clients = [Client(), Client(), Client(), Client()]
    for cl in clients:
        cl.fetch_headers = lambda u: (_ for _ in ()).throw(OSError("connection reset"))
    monkeypatch.setattr(
        scan,
        "get_provider",
        lambda n: SimpleNamespace(
            connect=lambda p: clients.pop(0),
            default_exclude_folders=lambda: [],
        ),
    )
    out = scan.scan_mailbox(profile, resume=False)
    assert out["batch_fallbacks"] and out["errors"]

    # Empty selected folder clears server UIDs.
    cl = Client()
    cl.select = lambda *a, **k: (0, 10)
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(cl))
    assert scan.scan_mailbox(profile)["messages_upserted"] == 0
    client = Client()
    client.uid_search_all_above = lambda n: (_ for _ in ()).throw(ValueError("search"))
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    assert scan.scan_mailbox(profile)["errors"]


def test_scan_per_uid_connection_recovery(profile, monkeypatch):
    import mail_janitor.scan as scan

    first, second = Client(), Client()

    def first_fetch(uids):
        if len(uids) > 1:
            raise ValueError("batch poison")
        raise OSError("connection reset")

    first.fetch_headers = first_fetch
    second.fetch_headers = lambda u: [
        r for r in second.headers if r["uid"] in u
    ]
    clients = [first, second]
    monkeypatch.setattr(
        scan,
        "get_provider",
        lambda n: SimpleNamespace(
            connect=lambda p: clients.pop(0),
            default_exclude_folders=lambda: [],
        ),
    )
    monkeypatch.setattr(scan, "with_backoff", lambda fn: fn())
    out = scan.scan_mailbox(profile, resume=False)
    assert out["reconnects"] == 1 and out["messages_upserted"] == 2


def test_scan_backfill_blank_and_refresh(profile, monkeypatch, tmp_path):
    import mail_janitor.scan as scan

    add_message(profile, 1, sender="", domain="")
    add_message(profile, 2, sender="ok@x")
    c = init_db(profile.db_path)
    c.execute("UPDATE messages SET list_unsubscribe=1 WHERE uid=2")
    c.commit()
    c.close()
    client = Client()
    client.imap = SimpleNamespace(
        uid=lambda *a: (
            "OK",
            [
                (
                    b"1 (UID 1)",
                    b"From: fixed@x\r\nSubject: fixed\r\nList-Unsubscribe: x\r\n\r\n",
                )
            ],
        )
    )
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    monkeypatch.setattr(scan, "Path", lambda p: tmp_path / "status")
    out = scan.backfill_list_unsubscribe(profile)
    assert out["updated_to_1"] == 1 and out["skipped_already_1"] == 1
    stats = scan.blank_header_stats(profile)
    assert stats["blank"] == 1 and stats["needs_repair"]
    client.headers = [
        {
            **client.headers[0],
            "uid": 1,
            "from_addr": "fixed@x",
            "subject": "fixed",
        }
    ]
    repaired = scan.refresh_blank_headers(profile)
    assert repaired["repaired"] == 1 and repaired["samples"]
    assert scan.blank_header_stats(profile)["blank"] == 0


def test_scan_backfill_and_refresh_failures(profile, monkeypatch, tmp_path):
    import mail_janitor.scan as scan

    add_message(profile, 1, sender="")
    client = Client()
    client.select = lambda *a, **k: (_ for _ in ()).throw(ValueError("select"))
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    monkeypatch.setattr(scan, "with_backoff", lambda fn: fn())
    monkeypatch.setattr(scan, "Path", lambda p: tmp_path / "missing" / "status")
    assert scan.backfill_list_unsubscribe(profile)["errors"]
    assert scan.refresh_blank_headers(profile)["errors"]

    client = Client()
    client.fetch_headers = lambda u: []
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    assert scan.refresh_blank_headers(profile)["missing_on_server"] == 1
    client.fetch_headers = lambda u: [{**client.headers[0], "from_addr": "", "subject": ""}]
    assert scan.refresh_blank_headers(profile)["still_blank"] == 1


def test_scan_backfill_edge_batches(profile, monkeypatch, tmp_path):
    import mail_janitor.scan as scan

    add_message(profile, 1)
    add_message(profile, 2, folder=profile.ready_folder)
    client = Client()
    calls = {"n": 0}

    def uid(*args):
        calls["n"] += 1
        if calls["n"] == 1:
            return "NO", []
        raise ValueError("fetch")

    client.imap = SimpleNamespace(uid=uid)
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    monkeypatch.setattr(scan, "with_backoff", lambda fn: fn())
    monkeypatch.setattr(scan, "Path", lambda p: tmp_path / "status")
    out = scan.backfill_list_unsubscribe(profile)
    assert out["checked"] == 0

    # Successful response missing one UID and with a flag=0 row.
    client.imap = SimpleNamespace(
        uid=lambda *a: (
            "OK",
            [(b"1 (UID 1)", b"From: a@x\r\n\r\n")],
        )
    )
    out = scan.backfill_list_unsubscribe(profile)
    assert out["still_0"] >= 1

    # Refresh fetch exception.
    c = init_db(profile.db_path)
    c.execute("UPDATE messages SET from_addr='' WHERE folder='Inbox'")
    c.commit()
    c.close()
    client.fetch_headers = lambda u: (_ for _ in ()).throw(ValueError("fetch"))
    assert scan.refresh_blank_headers(profile)["errors"]


def test_scan_backfill_missing_and_fetch_exception(profile, monkeypatch, tmp_path):
    import mail_janitor.scan as scan

    add_message(profile, 1)
    add_message(profile, 2)
    add_message(profile, 3, folder="Already")
    c = init_db(profile.db_path)
    c.execute("UPDATE messages SET list_unsubscribe=1 WHERE folder='Already'")
    c.commit()
    c.close()
    client = Client()
    monkeypatch.setattr(scan, "get_provider", lambda n: provider_for(client))
    monkeypatch.setattr(scan, "with_backoff", lambda fn: fn())
    monkeypatch.setattr(scan, "Path", lambda p: tmp_path / "status")
    client.imap = SimpleNamespace(
        uid=lambda *a: (
            "OK",
            [(b"1 (UID 1)", b"From: a@x\r\n\r\n")],
        )
    )
    out = scan.backfill_list_unsubscribe(profile)
    assert out["missing_on_server"] == 1

    # A folder with no pending rows is skipped.
    assert out["folders"] == 1
    c = init_db(profile.db_path)
    c.execute("UPDATE messages SET list_unsubscribe=0 WHERE folder='Inbox'")
    c.commit()
    c.close()
    client.imap = SimpleNamespace(
        uid=lambda *a: (_ for _ in ()).throw(ValueError("fetch"))
    )
    assert scan.backfill_list_unsubscribe(profile)["errors"]

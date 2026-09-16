from __future__ import annotations

import email
import imaplib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from mail_janitor.config import Profile
from mail_janitor.providers.base import FolderInfo, ImapClient, chunked, with_backoff


@pytest.fixture
def profile(tmp_path: Path) -> Profile:
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "rules.yaml").write_text("keep: []\nstage: []\n", encoding="utf-8")
    (tmp_path / "firewall.yaml").write_text(
        "enabled: true\nwatch_folder: Inbox\nquarantine_folder: Quarantine\n"
        "poll_seconds: 1\nheuristic_quarantine: true\nallow: []\nblock: []\n",
        encoding="utf-8",
    )
    (tmp_path / "config.toml").write_text(
        'provider = "imap"\nemail = "test@example.com"\nimap_host = "imap.example.com"\n',
        encoding="utf-8",
    )
    return Profile(
        name="test",
        path=tmp_path,
        provider="imap",
        email="test@example.com",
        imap_host="imap.example.com",
        imap_port=993,
        imap_ssl=True,
        app_password="pw",
        scan_batch_size=2,
        move_batch_size=2,
    )


class FakeImap:
    def __init__(self):
        self.calls = []
        self.responses = {}

    def login(self, *args):
        self.calls.append(("login", args))
        return self.responses.get("login", ("OK", []))

    def close(self):
        self.calls.append(("close",))
        if self.responses.get("close_exc"):
            raise RuntimeError("close")

    def logout(self):
        self.calls.append(("logout",))
        if self.responses.get("logout_exc"):
            raise RuntimeError("logout")

    def list(self):
        return self.responses.get("list", ("OK", []))

    def select(self, *args, **kwargs):
        self.calls.append(("select", args, kwargs))
        return self.responses.get("select", ("OK", [b"2"]))

    def response(self, *args):
        return self.responses.get("response", ("OK", [b"77"]))

    def status(self, *args):
        if self.responses.get("status_exc"):
            raise RuntimeError("status")
        return self.responses.get("status", ("OK", [b"X (UIDVALIDITY 88)"]))

    def uid(self, *args):
        self.calls.append(("uid", args))
        key = args[0].lower()
        val = self.responses.get((key, args[1] if len(args) > 1 else None))
        if isinstance(val, Exception):
            raise val
        return val or self.responses.get(key, ("OK", [b""]))

    def create(self, *args):
        return self.responses.get("create", ("OK", []))


def client_with(fake: FakeImap) -> ImapClient:
    c = ImapClient("host", 993, "e", "p")
    c._imap = fake
    return c


def test_imap_connect_close_context_and_property(monkeypatch):
    good = FakeImap()
    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda *a, **k: good)
    c = ImapClient("h", 1, "e", "p")
    c.connect()
    assert c.imap is good
    c.close()
    c.close()

    bad = FakeImap()
    bad.responses.update(login=("NO", []), close_exc=True, logout_exc=True)
    monkeypatch.setattr(imaplib, "IMAP4", lambda *a, **k: bad)
    c = ImapClient("h", 1, "e", "p", ssl=False)
    with pytest.raises(RuntimeError):
        c.connect()
    c.close()
    with pytest.raises(RuntimeError, match="Not connected"):
        _ = c.imap

    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda *a, **k: good)
    with ImapClient("h", 1, "e", "p") as entered:
        assert entered._imap is good


def test_imap_list_select_search_and_folder_helpers():
    f = FakeImap()
    c = client_with(f)
    f.responses["list"] = (
        "OK",
        [None, b'(\\HasNoChildren) "/" "Inbox"', b"junk", '(X) NIL Archive'],
    )
    assert [x.name for x in c.list_folders()] == ["Inbox", "Archive"]
    f.responses["list"] = ("NO", None)
    assert c.list_folders() == []

    assert c.select("Inbox") == (2, 77)
    f.responses["response"] = ("OK", [b"bad"])
    assert c.select("Inbox") == (2, 88)
    f.responses["status"] = ("NO", [])
    assert c.select("Inbox") == (2, None)
    f.responses["status_exc"] = True
    assert c.select("Inbox") == (2, None)
    f.responses["select"] = ("NO", [b"x"])
    with pytest.raises(RuntimeError):
        c.select("Inbox")

    f.responses["select"] = ("OK", [None])
    assert c.select("Inbox")[0] == 0
    f.responses["search"] = ("OK", [b"1 x 2 5"])
    assert c.uid_search_all_above(2) == [5]
    assert c.uid_search_all_above(0) == [1, 2, 5]
    f.responses["search"] = ("NO", [])
    assert c.uid_search_all_above(0) == []
    assert c._quote("Inbox/A") == "Inbox/A"
    assert c._quote('A "B" \\ C') == '"A \\"B\\" \\\\ C"'


def test_imap_fetch_headers_body_and_attachment(monkeypatch):
    f = FakeImap()
    c = client_with(f)
    hdr = b"From: A <a@example.com>\r\nSubject: Hello\r\nList-Unsubscribe: <x>\r\n\r\n"
    f.responses["fetch"] = (
        "OK",
        [(b"1 (UID 1 FLAGS (\\Seen) RFC822.SIZE 123)", hdr), b")"],
    )
    rows = c.fetch_headers([1])
    assert rows[0]["uid"] == 1 and rows[0]["list_unsubscribe"] == 1
    assert c.fetch_headers([]) == []
    f.responses["fetch"] = ("NO", [])
    assert c.fetch_headers([1]) == []

    # Header fetch followed by separate BODYSTRUCTURE fetch.
    calls = iter(
        [
            ("OK", [(b"1 (UID 1 RFC822.SIZE 2)", hdr)]),
            ("OK", [(b'1 (UID 1 BODYSTRUCTURE ("TEXT" "PLAIN"))', b"")]),
        ]
    )
    f.uid = lambda *a: next(calls)
    assert c.fetch_headers([1])[0]["has_attachment"] == 0

    f.uid = lambda *a: (_ for _ in ()).throw(RuntimeError("bodystructure"))
    with pytest.raises(RuntimeError):
        c.fetch_headers([1])

    raw = b"From: a@x\r\nTo: b@x\r\nSubject: S\r\n\r\nBody"
    f.uid = lambda *a: ("OK", [(b"meta", raw)])
    kind, text = c.fetch_body(1)
    assert kind == "text/plain" and "Body" in text
    f.uid = lambda *a: ("NO", [])
    with pytest.raises(RuntimeError, match="Failed"):
        c.fetch_body(1)
    f.uid = lambda *a: ("OK", [b"x"])
    with pytest.raises(RuntimeError, match="Empty"):
        c.fetch_body(1)

    for meta, expected in [
        (b"x", None),
        (b'(BODYSTRUCTURE "attachment")', 1),
        (b'(BODYSTRUCTURE "filename")', 1),
        (b'(BODYSTRUCTURE "mixed" boundary)', 1),
        (b"(BODYSTRUCTURE text)", 0),
        (b"(other)", None),
    ]:
        assert c._attachment_from_meta(meta) == expected


def test_imap_parse_rows_extract_and_text(monkeypatch):
    c = client_with(FakeImap())
    hdr = b"From: a@example.com\r\nSubject: hi\r\n\r\n"
    data = [
        None,
        b")",
        (b"1 (UID 1 RFC822.SIZE 9 FLAGS (Seen))", hdr),
        b"2 (UID 2 RFC822.SIZE 10)",
        hdr,
        b"not a uid",
    ]
    rows = c._parse_fetch_headers(data)
    assert [r["uid"] for r in rows] == [1, 2]
    monkeypatch.setattr(
        "mail_janitor.providers.base.parse_header_bytes",
        lambda b: (_ for _ in ()).throw(ValueError("bad")),
    )
    row = c._row_from_fetch(b"(UID 3)", b"x")
    assert row and row["from_addr"] == ""
    assert c._row_from_fetch(b"no uid", hdr) is None

    assert c._extract_body_bytes([(b"m", bytearray(b"body"))]) == b"body"
    assert c._extract_body_bytes([b"(BODY " + b"x" * 100, b"z" * 101]) == b"z" * 101
    assert c._extract_body_bytes([b"x"]) is None

    plain = email.message_from_string("From: a\nContent-Type: text/plain\n\nhello")
    assert c._extract_text_part(plain) == "hello"
    multipart = email.message_from_string(
        "Content-Type: multipart/alternative; boundary=x\n\n"
        "--x\nContent-Type: text/html\n\n<b>hello</b>\n--x--"
    )
    assert "hello" in c._extract_text_part(multipart)
    attached = email.message_from_string(
        "Content-Type: multipart/mixed; boundary=x\n\n"
        "--x\nContent-Type: text/plain\nContent-Disposition: attachment\n\nignore\n--x--"
    )
    assert c._extract_text_part(attached) == ""
    assert "[No plain/html" in c._message_to_text(attached)


def test_imap_moves_and_copyuid():
    f = FakeImap()
    c = client_with(f)
    assert c.move_uids([], "D") == {}
    f.responses["move"] = ("OK", [b"[COPYUID 1 1:2 11:12]"])
    assert c.move_uids([1, 2], "D") == {1: 11, 2: 12}
    assert c.move_uid(1, "D") == 11

    f.responses["move"] = RuntimeError("unsupported")
    f.responses["copy"] = ("OK", [b"[COPYUID 1 1,2 21,22]"])
    assert c.move_uids([1, 2], "D") == {1: 21, 2: 22}
    f.responses["copy"] = ("NO", [b"denied"])
    with pytest.raises(RuntimeError, match="COPY failed"):
        c.move_uids([1], "D")
    f.responses["copy"] = ("NO", [])
    with pytest.raises(RuntimeError):
        c.move_uids([1], "D")

    assert c._parse_copyuid_map(None, [1]) == {1: None}
    assert c._parse_copyuid_map([b"COPYUID 9 x 44"], [1]) == {1: 44}
    assert c._parse_copyuid_map([(b"COPYUID 9 4 40", "x")], [4]) == {4: 40}
    # Server source differs from request; known server pairs are retained.
    assert c._parse_copyuid_map([b"COPYUID 9 8 80"], [4]) == {4: None, 8: 80}
    f.responses["create"] = ("BAD", [])
    c.ensure_folder("D")


def test_with_backoff_and_chunked(monkeypatch):
    monkeypatch.setattr("mail_janitor.providers.base.time.sleep", lambda x: None)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 2:
            raise OSError("x")
        return 3

    assert with_backoff(flaky, retries=2) == 3
    with pytest.raises(OSError):
        with_backoff(lambda: (_ for _ in ()).throw(OSError("x")), retries=1)
    assert list(chunked([1, 2, 3], 2)) == [[1, 2], [3]]


def test_config_profiles_and_helpers(tmp_path, monkeypatch, profile):
    import mail_janitor.config as config

    root = tmp_path / "profiles"
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))
    assert config.profiles_dir() == root.resolve()
    monkeypatch.delenv("MAIL_JANITOR_PROFILES_DIR")
    assert config.profiles_dir() == config.REPO_ROOT / "profiles"
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))
    assert config.list_profiles() == []

    root.mkdir()
    for name in ("one", "_example", ".hidden", "file"):
        p = root / name
        if name == "file":
            p.write_text("x")
        else:
            p.mkdir()
            (p / "config.toml").write_text('provider="imap"\nemail="e@x"\n')
    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: False)
    assert config.list_profiles() == ["one"]
    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: True)
    monkeypatch.setattr("mail_janitor.client_sessions.current_uid", lambda: "one")
    assert config.list_profiles() == ["one"]
    monkeypatch.setattr("mail_janitor.client_sessions.current_uid", lambda: None)
    assert config.list_profiles() == []

    assert profile.effective_stage_folders() == ["Inbox"]
    profile.stage_folders = ["Inbox", "Archive"]
    assert profile.effective_stage_folders() == ["Inbox", "Archive"]
    assert profile.stage_scope_label() == "Inbox, Archive"
    assert profile.stage_scope_label("Spam") == "Spam"
    profile.stage_folders = []
    profile.stage_inbox_only = False
    assert profile.effective_stage_folders() is None
    assert profile.stage_scope_label() == "all folders"
    rule = SimpleNamespace(folder="Spam")
    assert profile.stage_folder_sql(rule) == ("", [])
    rule.folder = None
    assert profile.stage_folder_sql(rule) == ("", [])
    profile.stage_inbox_only = True
    assert profile.stage_folder_sql(rule) == (" AND folder IN (?)", ["Inbox"])
    assert profile.db_path.name == "mail.db"
    assert profile.rules_path.name == "rules.yaml"
    assert profile.audit_path.name == "audit.jsonl"
    assert profile.firewall_path.name == "firewall.yaml"
    assert profile.config_path.name == "config.toml"


def test_config_load_create_delete_credentials(tmp_path, monkeypatch):
    import mail_janitor.config as config

    root = tmp_path / "profiles"
    example = root / "_example"
    example.mkdir(parents=True)
    for name, text in {
        "config.toml": 'provider="imap"\nemail="x@y"\nimap_host="h"\n',
        "rules.yaml": "keep: []\nstage: []\n",
        ".env.example": "MAIL_JANITOR_EMAIL=\n",
    }.items():
        (example / name).write_text(text)
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))
    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: False)
    with pytest.raises(FileNotFoundError):
        config.load_profile("missing")
    (root / "bad").mkdir()
    with pytest.raises(FileNotFoundError):
        config.load_profile("bad")

    dest = config.ensure_profile_files("foo")
    assert (dest / "firewall.yaml").exists() and (dest / ".env").exists()
    (dest / ".env").unlink()
    monkeypatch.setenv("MAIL_JANITOR_EMAIL", "env@example.com")
    monkeypatch.setenv("MAIL_JANITOR_APP_PASSWORD", "secret")
    p = config.load_profile("foo")
    assert p.email == "env@example.com" and p.app_password == "secret"
    monkeypatch.delenv("MAIL_JANITOR_EMAIL")
    monkeypatch.delenv("MAIL_JANITOR_APP_PASSWORD")
    with pytest.raises(ValueError, match="APP_PASSWORD"):
        config.load_profile("foo")
    (dest / "config.toml").write_text('provider="imap"\nimap_host="h"\n')
    with pytest.raises(ValueError, match="Set email"):
        config.load_profile("foo")
    (dest / "config.toml").write_text(
        'provider="imap"\nemail="x@y"\nimap_host="h"\n'
    )

    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: True)
    monkeypatch.setattr("mail_janitor.client_sessions.load_credentials", lambda n: None)
    p = config.load_profile("foo")
    assert p.email == "x@y" and p.app_password == ""
    monkeypatch.setattr(
        "mail_janitor.client_sessions.load_credentials", lambda n: ("c@x", "pw")
    )
    assert config.load_profile("foo").email == "c@x"

    for bad in ("", ".", "example"):
        with pytest.raises(ValueError):
            config._safe_profile_name(bad)
    assert config._safe_profile_name(" My Box! ") == "my-box"
    assert config._toml_string_list(['a"b', "c\\d"]) == '["a\\"b", "c\\\\d"]'
    assert "x = 2" in config._upsert_toml_line("x = 1\n", "x", "2")
    assert config._upsert_toml_line("", "x", "2") == "x = 2\n"
    assert config._remove_toml_key("x=1\ny=2\n", "x") == "y=2\n"

    monkeypatch.setattr(config, "apply_provider_pack", lambda *a, **k: dest)
    assert config.create_profile("new")["profile"] == "new"
    with pytest.raises(ValueError, match="already"):
        config.create_profile("foo")
    with pytest.raises(ValueError, match="another mailbox"):
        config.delete_profile("foo", active="foo")
    with pytest.raises(FileNotFoundError):
        config.delete_profile("none")
    assert config.delete_profile("new")["deleted"] == "new"

    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: False)
    config.write_profile_credentials("foo", "new@example.com", " pass ")
    assert "MAIL_JANITOR_APP_PASSWORD=pass" in (dest / ".env").read_text()
    with pytest.raises(ValueError):
        config.write_profile_credentials("foo", "bad", "x")
    with pytest.raises(ValueError):
        config.write_profile_credentials("foo", "a@b", "")
    stored = []
    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: True)
    monkeypatch.setattr(
        "mail_janitor.client_sessions.store_credentials",
        lambda *a: stored.append(a),
    )
    config.write_profile_credentials("foo", "a@b", "x")
    assert stored


def test_config_pack_summaries_save_and_imap(tmp_path, monkeypatch, profile):
    import mail_janitor.config as config

    root = tmp_path / "profiles"
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))
    example = root / "_example"
    example.mkdir(parents=True)
    (example / "config.toml").write_text('provider="imap"\nemail="e@x"\n')
    (example / "rules.yaml").write_text("keep: []\nstage: []\n")
    (example / ".env.example").write_text("")
    config.apply_provider_pack("x", "yahoo")
    txt = (root / "x" / "config.toml").read_text()
    assert 'provider = "yahoo"' in txt
    with pytest.raises(ValueError, match="host"):
        config.apply_provider_pack("z", "imap")
    config.apply_provider_pack("z", "imap", imap_host="custom")

    monkeypatch.setattr(config, "list_profiles", lambda: ["x"])
    (root / "x" / ".env").write_text("MAIL_JANITOR_EMAIL=env@x\n")
    (root / "x" / "mail.db").touch()
    summary = config.profile_summaries()[0]
    assert summary["email"] == "env@x" and summary["has_db"]
    (root / "x" / "config.toml").write_text("[broken")
    assert config.profile_summaries()[0]["provider"] == ""
    # Bad env reads are ignored.
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **k: (
            (_ for _ in ()).throw(OSError("read"))
            if self.name == ".env"
            else "[broken"
        ),
    )
    assert config.profile_summaries()[0]["email"] == ""
    monkeypatch.undo()
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))

    profile.path.mkdir(exist_ok=True)
    profile.config_path.write_text("stage_inbox_only = true\n")
    config.save_stage_folders(profile, [" Inbox ", "Archive"])
    assert "stage_folders" in profile.config_path.read_text()
    config.save_stage_folders(profile, None)
    assert "stage_inbox_only = false" in profile.config_path.read_text()
    with pytest.raises(ValueError):
        config.save_stage_folders(profile, [])

    fake = MagicMock()
    fake.list_folders.return_value = [FolderInfo("Inbox", "")]
    provider = MagicMock()
    provider.connect.return_value = fake
    monkeypatch.setattr(config, "get_provider", lambda n: provider, raising=False)
    monkeypatch.setattr("mail_janitor.providers.get_provider", lambda n: provider)
    out = config.test_imap_connection(profile)
    assert out["folder_count"] == 1
    fake.close.assert_called_once()


def test_db_all_helpers(tmp_path):
    from mail_janitor import db

    path = tmp_path / "x.db"
    conn = db.init_db(path)
    db.upsert_message(
        conn,
        {
            "folder": "Inbox",
            "uid": 1,
            "from_addr": "a@x",
            "size": 2,
            "has_attachment": 1,
        },
    )
    db.upsert_message(conn, {"folder": "Inbox", "uid": 1, "subject": "updated"})
    db.upsert_message(conn, {"folder": "Other", "uid": 2})
    db.set_scan_progress(conn, "Inbox", 2, 4, "now")
    conn.commit()
    assert db.get_scan_progress(conn, "Inbox") == (2, 4)
    assert db.get_scan_progress(conn, "none") == (0, None)
    assert db.message_count(conn) == 2
    assert db.list_indexed_folders(conn)[0]["folder"] in {"Inbox", "Other"}
    assert db.folder_message_count(conn, "inbox") == 1
    assert db.inbox_message_count(conn) == 1
    assert db.staged_count(conn) == 0
    conn.execute(
        "INSERT INTO staged(folder,uid,rule_id,included) VALUES('Inbox',1,'r',0)"
    )
    assert db.staged_count(conn, included_only=False) == 1
    conn.close()

    with db.db_session(path) as c:
        c.execute("UPDATE messages SET subject='ok'")
    with pytest.raises(RuntimeError):
        with db.db_session(path) as c:
            c.execute("UPDATE messages SET subject='bad'")
            raise RuntimeError("rollback")

    # Exercise migration from the oldest schema.
    old = tmp_path / "old.db"
    c = db.connect(old)
    c.execute("CREATE TABLE messages(folder TEXT, uid INTEGER)")
    c.commit()
    db._migrate(c)
    assert "has_attachment" in {
        r[1] for r in c.execute("PRAGMA table_info(messages)").fetchall()
    }
    c.close()


def test_config_packaged_template_fallback(tmp_path, monkeypatch):
    import mail_janitor.config as config

    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(tmp_path / "empty"))
    path = config.ensure_profile_files("fallback")
    assert path.exists()


def test_config_missing_personal_email(tmp_path, monkeypatch):
    import mail_janitor.config as config

    root = tmp_path / "profiles"
    p = root / "x"
    p.mkdir(parents=True)
    (p / "config.toml").write_text('provider="imap"\nimap_host="h"\n')
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))
    monkeypatch.setenv("MAIL_JANITOR_EMAIL", "")
    monkeypatch.setenv("MAIL_JANITOR_APP_PASSWORD", "")
    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: False)
    with pytest.raises(ValueError, match="Set email"):
        config.load_profile("x")


def test_config_loads_existing_dotenv(tmp_path, monkeypatch):
    import mail_janitor.config as config

    root = tmp_path / "profiles"
    p = root / "x"
    p.mkdir(parents=True)
    (p / "config.toml").write_text('provider="imap"\nimap_host="h"\n')
    (p / ".env").write_text("placeholder")
    monkeypatch.setenv("MAIL_JANITOR_PROFILES_DIR", str(root))
    monkeypatch.setattr("mail_janitor.client_sessions.client_mode", lambda: False)

    def load(path, override):
        monkeypatch.setenv("MAIL_JANITOR_EMAIL", "a@x")
        monkeypatch.setenv("MAIL_JANITOR_APP_PASSWORD", "pw")

    monkeypatch.setattr(config, "load_dotenv", load)
    assert config.load_profile("x").email == "a@x"

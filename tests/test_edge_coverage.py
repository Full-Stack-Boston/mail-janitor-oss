from __future__ import annotations

import email
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest


def test_provider_adapters_and_registry(monkeypatch, tmp_path):
    from mail_janitor.config import Profile
    from mail_janitor.providers import get_provider
    from mail_janitor.providers import generic, gmail_imap, yahoo, zoho
    from mail_janitor.providers.packs import get_pack

    p = Profile("p", tmp_path, "imap", "e", "host", 993, True, app_password="pw")

    class C:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.connected = False

        def connect(self):
            self.connected = True

    for module, cls in [
        (generic, generic.GenericImapProvider),
        (gmail_imap, gmail_imap.GmailImapProvider),
        (yahoo, yahoo.YahooProvider),
        (zoho, zoho.ZohoProvider),
    ]:
        monkeypatch.setattr(module, "ImapClient", C)
        provider = cls()
        client = provider.connect(p)
        assert client.connected
        assert provider.default_exclude_folders()
        assert provider.trash_folder_candidates()
    p.imap_host = ""
    with pytest.raises(ValueError):
        generic.GenericImapProvider().connect(p)
    assert gmail_imap.GmailImapProvider().connect(p).kwargs["host"]
    assert zoho.ZohoProvider().connect(p).kwargs["host"]
    assert get_pack("gmail").id == "gmail_imap"
    with pytest.raises(ValueError):
        get_pack("bad")
    with pytest.raises(ValueError):
        get_provider("bad")


def test_notify_all_paths(monkeypatch):
    import mail_janitor.notify as n

    monkeypatch.delenv("NATHAN_URL", raising=False)
    monkeypatch.delenv("NATHAN_API_KEY", raising=False)
    assert not n.notify_job("x", "y")
    monkeypatch.setenv("NATHAN_URL", "https://nathan")
    monkeypatch.setenv("NATHAN_API_KEY", "key")

    class Resp:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(n.urllib.request, "urlopen", lambda *a, **k: Resp())
    assert n.notify_job("x" * 200, "y" * 600, priority=4)
    Resp.status = 500
    assert not n.notify_job("x", "y")
    monkeypatch.setattr(
        n.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(OSError("down")),
    )
    assert not n.notify_job("x", "y")


def test_uid_progress_and_parse_edges(monkeypatch):
    from mail_janitor import parse_headers as h
    from mail_janitor import progress
    from mail_janitor import uidset

    assert uidset.expand_uid_set(b"5:3,,8") == [3, 4, 5, 8]
    assert uidset.expand_uid_set(" ") == []
    with pytest.raises(ValueError):
        uidset.expand_uid_set("x")
    assert uidset.compact_uid_set([]) == ""
    assert uidset.compact_uid_set([1, 2, 4, 4]) == "1:2,4"
    assert uidset.map_copyuid_sets("1:3", "4:5") == {1: 4, 2: 5}

    assert progress.parse_iso(None) is None
    assert progress.parse_iso("bad") is None
    now = datetime(2020, 1, 2, tzinfo=timezone.utc)
    assert progress.elapsed_seconds("2020-01-01T00:00:00Z", now=now) == 86400
    assert progress.elapsed_seconds(None) is None
    for value, expected in [
        (None, "—"),
        ("bad", "—"),
        (-1, "—"),
        (5, "5s"),
        (65, "1m 05s"),
        (3660, "1h 01m"),
    ]:
        assert progress.format_duration(value) == expected
    assert progress.eta_seconds(done=1, total=2, elapsed_sec=None) is None
    assert progress.eta_seconds(done="x", total=2, elapsed_sec=1) is None
    assert progress.eta_seconds(done=1, total=None, elapsed_sec=1) is None
    assert progress.eta_seconds(done=2, total=2, elapsed_sec=1, min_done=1) == 0
    assert progress.eta_seconds(done=0, total=2, elapsed_sec=1, min_done=0) is None
    snap = progress.progress_snapshot(done=1, total=None, started_at=None)
    assert snap["total"] is None
    snap = progress.progress_snapshot(
        done=5, total=10, started_at="2020-01-01T00:00:00Z", min_done=1
    )
    assert snap["pct"] == 50

    monkeypatch.setattr(
        h.email.header,
        "decode_header",
        lambda v: (_ for _ in ()).throw(ValueError("bad")),
    )
    assert h.decode_header_value(" x ") == "x"
    monkeypatch.undo()
    assert h.decode_header_value(None) == ""
    assert h.decode_header_value("=?x-bad?b?YQ==?=")
    assert h.extract_address(None) == ""
    monkeypatch.setattr(h.email.utils, "parseaddr", lambda x: ("", ""))
    assert h.extract_address("A@EXAMPLE.COM") == "a@example.com"
    assert h.extract_address("nonsense") == "nonsense"
    assert h.extract_domain("none") == ""
    assert h.parse_date_ts(None) == (None, "")
    assert h.parse_date_ts("bad")[0] is None
    assert h.parse_date_ts("Wed, 01 Jan 2020 00:00:00")[0]
    assert h.parse_header_bytes("From: a@x.com\n")["from_addr"] == "a@x.com"
    monkeypatch.setattr(
        h,
        "HeaderParser",
        lambda: (_ for _ in ()).throw(ValueError("bad")),
    )
    assert h.parse_header_bytes(b"x")["from_addr"] == ""
    assert h.format_size(None) == "0 B"
    assert h.format_size(1024).endswith("KB")
    assert h.format_size(1024**5).endswith("TB")
    assert h.format_ts(None) == ""
    assert "2020" in h.format_ts(1577836800)


def test_base_provider_remaining_edges(monkeypatch):
    from mail_janitor.providers.base import ImapClient

    c = ImapClient("h", 1, "e", "p")

    class I:
        def uid(self, *a):
            if a[0] == "fetch" and "HEADER" in a[-1]:
                return "OK", [(b"1 (UID 1)", b"From: a@x.com\n")]
            return "OK", [
                (b"1 (UID 1 BODYSTRUCTURE attachment)", b""),
                b"2 (UID 2 BODYSTRUCTURE text)",
                "ignore",
            ]

    c._imap = I()
    assert c.fetch_headers([1])[0]["has_attachment"] == 1

    calls = {"n": 0}

    def uid(*a):
        calls["n"] += 1
        if calls["n"] == 1:
            return "OK", [(b"1 (UID 1)", b"From: a@x.com\n")]
        raise ValueError("structure")

    c._imap = SimpleNamespace(uid=uid)
    assert c.fetch_headers([1])[0]["uid"] == 1

    # Multipart decode exceptions, None payload, plain-over-html and exception fallback.
    msg = email.message_from_string(
        "Content-Type: multipart/alternative; boundary=x\n\n"
        "--x\nContent-Type: text/html\n\n<b>html</b>\n"
        "--x\nContent-Type: text/plain\n\nplain\n--x--"
    )
    assert "plain" in c._extract_text_part(msg)

    class Part:
        def get_content_type(self):
            return "text/plain"

        def get(self, k):
            return ""

        def get_payload(self, decode=True):
            raise ValueError("bad")

    class Multi:
        def is_multipart(self):
            return True

        def walk(self):
            return [Part()]

    assert c._extract_text_part(Multi()) == ""

    class Bad:
        def is_multipart(self):
            return False

        def get_payload(self, *args, **kwargs):
            if args or kwargs:
                raise ValueError("x")
            return "fallback"

    assert c._extract_text_part(Bad()) == "fallback"

    class NonePayload(Bad):
        def get_payload(self, *args, **kwargs):
            return None if args or kwargs else "raw"

    assert c._extract_text_part(NonePayload()) == "raw"


def test_firewall_policy_edges(tmp_path):
    from mail_janitor.firewall_policy import (
        FirewallConfig,
        _message_matches_rule,
        add_allow_sender,
        add_block_domain,
        add_block_sender,
        load_firewall,
        save_firewall,
    )
    from mail_janitor.rules import Rule

    path = tmp_path / "fw.yaml"
    cfg = load_firewall(path)
    assert path.exists() and cfg.poll_seconds >= 15
    with pytest.raises(ValueError):
        save_firewall(FirewallConfig())
    cfg.path = path
    cfg.allow = [
        Rule(
            id="x",
            label="X",
            from_domain="x",
            from_address="a@x",
            subject_contains="hi",
            older_than_days=2,
            folder="Inbox",
            has_list_unsubscribe=False,
            min_size=2,
            match="any",
        )
    ]
    save_firewall(cfg)
    assert load_firewall(path).allow

    msg = {
        "from_domain": "x",
        "from_addr": "a@x",
        "subject": "HI",
        "folder": "Inbox",
        "list_unsubscribe": 0,
        "size": 3,
    }
    assert _message_matches_rule(msg, cfg.allow[0])
    assert not _message_matches_rule(msg, Rule(id="none"))
    all_rule = Rule(
        id="all",
        from_domain="x",
        from_address="bad",
        match="all",
    )
    assert not _message_matches_rule(msg, all_rule)

    first = add_allow_sender(path, "A@X")
    assert add_allow_sender(path, "a@x").id == first.id
    blocked = add_block_sender(path, "B@X")
    assert add_block_sender(path, "b@x").id == blocked.id
    domain = add_block_domain(path, "X.COM")
    assert add_block_domain(path, "x.com").id == domain.id


def test_heuristic_edge_signals():
    from mail_janitor.heuristics import (
        annotate_domain,
        annotate_sender,
        looks_human_local,
        looks_random_local,
        marketing_ish_domain,
        score_message,
        _local_part,
    )

    assert not marketing_ish_domain(None)
    assert not marketing_ish_domain("gmail.com")
    assert marketing_ish_domain("news.shop.test")
    assert _local_part("plain") == "plain"
    assert _local_part("A@X") == "a"
    assert not looks_random_local(None)
    assert not looks_random_local("short")
    assert looks_random_local("abcdef12")
    assert looks_random_local("user123456")
    assert looks_random_local("bcdfghjkl")
    assert not looks_human_local(None)
    assert not looks_human_local("noreply.bot")
    assert looks_human_local("john.smith")
    junk = score_message(
        {
            "from_addr": "bcdfghjkl@news.x",
            "from_domain": "news.x",
            "subject": "Re: 50% off",
            "folder": "Spam",
            "list_unsubscribe": 1,
        }
    )
    assert junk["confidence"] == "junk" and "bulk-folder" in junk["flags"]
    assert score_message(
        {
            "from_addr": "john.smith@gmail.com",
            "from_domain": "gmail.com",
            "subject": "Re: hi",
        }
    )["confidence"] == "keep"
    assert annotate_sender(
        {"cnt": 40, "list_unsub_cnt": 10, "from_domain": "news.x"}
    )["heuristic_likely"]
    assert annotate_domain(
        {"cnt": 80, "list_unsub_cnt": 20, "from_domain": "news.x"}
    )["heuristic_likely"]

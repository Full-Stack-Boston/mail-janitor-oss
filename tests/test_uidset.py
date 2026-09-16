"""Tests for IMAP UID set helpers and COPYUID mapping."""

from mail_janitor.providers.base import ImapClient
from mail_janitor.uidset import compact_uid_set, expand_uid_set, map_copyuid_sets


def test_expand_uid_set_ranges_and_lists():
    assert expand_uid_set("1,3:5,10") == [1, 3, 4, 5, 10]
    assert expand_uid_set(b"7:9") == [7, 8, 9]
    assert expand_uid_set("42") == [42]


def test_compact_uid_set():
    assert compact_uid_set([5, 1, 2, 3, 10, 11]) == "1:3,5,10:11"
    assert compact_uid_set([7]) == "7"
    assert compact_uid_set([]) == ""


def test_map_copyuid_sets():
    assert map_copyuid_sets("1,3:4", "100:102") == {1: 100, 3: 101, 4: 102}


def test_parse_copyuid_map_batch():
    client = ImapClient("h", 993, "a", "b")
    data = [b"OK [COPYUID 12345 10:12 200:202] Done"]
    mapping = client._parse_copyuid_map(data, [10, 11, 12])
    assert mapping == {10: 200, 11: 201, 12: 202}


def test_parse_copyuid_map_single():
    client = ImapClient("h", 993, "a", "b")
    data = [b"OK [COPYUID 99 7 55] Done"]
    mapping = client._parse_copyuid_map(data, [7])
    assert mapping == {7: 55}

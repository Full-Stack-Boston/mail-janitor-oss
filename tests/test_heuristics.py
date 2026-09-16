"""Heuristic helpers for Insights."""

from mail_janitor.heuristics import (
    annotate_sender,
    looks_human_local,
    looks_random_local,
    marketing_ish_domain,
    score_message,
)


def test_marketing_ish_domain():
    assert marketing_ish_domain("news.temuemail.com")
    assert marketing_ish_domain("offers.aeropostale.com")
    assert not marketing_ish_domain("gmail.com")
    assert not marketing_ish_domain("acme-corp.com")


def test_annotate_sender_flags():
    row = annotate_sender(
        {
            "from_addr": "deals@offers.example.com",
            "from_domain": "offers.example.com",
            "cnt": 100,
            "list_unsub_cnt": 80,
        }
    )
    assert "list-unsub" in row["heuristic_flags"]
    assert "high-volume" in row["heuristic_flags"]
    assert "marketing-ish" in row["heuristic_flags"]
    assert row["heuristic_likely"] is True


def test_score_message_junk_vs_keep():
    junk = score_message(
        {
            "from_addr": "a28fhkkv@o9j.beigewind-chime.com",
            "from_domain": "o9j.beigewind-chime.com",
            "subject": "Slash your premiums: as low as $29/month",
            "list_unsubscribe": 1,
            "folder": "Inbox",
        }
    )
    assert junk["confidence"] == "junk"
    assert "list-unsub" in junk["flags"]

    keepish = score_message(
        {
            "from_addr": "jane.doe@gmail.com",
            "from_domain": "gmail.com",
            "subject": "Re: dinner plans",
            "list_unsubscribe": 0,
            "folder": "Inbox",
        }
    )
    assert keepish["confidence"] == "keep"
    assert "conversation" in keepish["flags"]


def test_local_part_helpers():
    assert looks_random_local("a28fhkkv")
    assert looks_human_local("jane.doe")
    assert not looks_human_local("noreply")
    assert not looks_human_local("no-reply")

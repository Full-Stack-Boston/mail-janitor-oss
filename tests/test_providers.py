"""Provider packs and registry."""

from mail_janitor.providers import get_provider, list_provider_ids
from mail_janitor.providers.packs import get_pack, list_provider_packs


def test_list_provider_packs():
    packs = list_provider_packs()
    ids = {p["id"] for p in packs}
    assert {"yahoo", "zoho", "gmail_imap", "imap"} <= ids
    yahoo = get_pack("yahoo")
    assert yahoo.imap_host.endswith("yahoo.com")
    assert "app password" in yahoo.auth_help.lower() or "App password" in yahoo.password_label


def test_get_provider_aliases():
    assert get_provider("yahoo").name == "yahoo"
    assert get_provider("zoho").name == "zoho"
    assert get_provider("gmail_imap").name == "gmail_imap"
    assert get_provider("gmail").name == "gmail_imap"
    assert get_provider("imap").name == "imap"
    assert "yahoo" in list_provider_ids()

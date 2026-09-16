"""Provider adapter protocol and registry."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mail_janitor.config import Profile
from mail_janitor.providers.base import ImapClient


@runtime_checkable
class Provider(Protocol):
    name: str

    def connect(self, profile: Profile) -> ImapClient: ...

    def default_exclude_folders(self) -> list[str]: ...

    def trash_folder_candidates(self) -> list[str]: ...


def _registry() -> dict[str, Provider]:
    from mail_janitor.providers import gmail_imap, generic, yahoo, zoho

    return {
        "yahoo": yahoo.YahooProvider(),
        "zoho": zoho.ZohoProvider(),
        "gmail_imap": gmail_imap.GmailImapProvider(),
        "gmail": gmail_imap.GmailImapProvider(),  # alias
        "imap": generic.GenericImapProvider(),
    }


def list_provider_ids() -> list[str]:
    return sorted({k for k in _registry() if k != "gmail"})


def get_provider(name: str) -> Provider:
    providers = _registry()
    key = name.lower().strip()
    if key not in providers:
        raise ValueError(
            f"Unknown provider '{name}'. Supported: {', '.join(list_provider_ids())}."
        )
    return providers[key]

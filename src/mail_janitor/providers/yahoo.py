"""Yahoo Mail IMAP provider."""

from __future__ import annotations

from mail_janitor.config import Profile
from mail_janitor.providers.base import ImapClient


class YahooProvider:
    name = "yahoo"

    def connect(self, profile: Profile) -> ImapClient:
        client = ImapClient(
            host=profile.imap_host,
            port=profile.imap_port,
            email=profile.email,
            password=profile.app_password,
            ssl=profile.imap_ssl,
        )
        client.connect()
        return client

    def default_exclude_folders(self) -> list[str]:
        return ["Trash", "Bulk Mail", "Spam", "ready2delete"]

    def trash_folder_candidates(self) -> list[str]:
        return ["Trash", "Deleted Items", "Deleted Messages"]

"""Generic IMAP provider (any host)."""

from __future__ import annotations

from mail_janitor.config import Profile
from mail_janitor.providers.base import ImapClient
from mail_janitor.providers.packs import get_pack


class GenericImapProvider:
    name = "imap"

    def connect(self, profile: Profile) -> ImapClient:
        if not profile.imap_host:
            raise ValueError("imap_host is required for the generic IMAP provider")
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
        return list(get_pack("imap").exclude_folders)

    def trash_folder_candidates(self) -> list[str]:
        return ["Trash", "Deleted Items", "Deleted Messages", "Junk"]

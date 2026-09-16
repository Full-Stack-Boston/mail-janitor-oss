"""Gmail via IMAP (app password). Native Gmail API is out of scope for now."""

from __future__ import annotations

from mail_janitor.config import Profile
from mail_janitor.providers.base import ImapClient
from mail_janitor.providers.packs import get_pack


class GmailImapProvider:
    name = "gmail_imap"

    def connect(self, profile: Profile) -> ImapClient:
        client = ImapClient(
            host=profile.imap_host or get_pack("gmail_imap").imap_host,
            port=profile.imap_port,
            email=profile.email,
            password=profile.app_password,
            ssl=profile.imap_ssl,
        )
        client.connect()
        return client

    def default_exclude_folders(self) -> list[str]:
        return list(get_pack("gmail_imap").exclude_folders)

    def trash_folder_candidates(self) -> list[str]:
        return ["[Gmail]/Trash", "Trash"]

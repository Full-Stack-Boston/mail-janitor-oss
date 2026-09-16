"""Shared provider pack metadata (setup wizard + defaults)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderPack:
    id: str
    label: str
    imap_host: str
    imap_port: int = 993
    imap_ssl: bool = True
    inbox_folder: str = "Inbox"
    trash_folder: str = "Trash"
    ready_folder: str = "ready2delete"
    kept_folder: str = "Intentionally Kept"
    exclude_folders: tuple[str, ...] = ()
    auth_help: str = ""
    password_label: str = "App password"


PACKS: dict[str, ProviderPack] = {
    "yahoo": ProviderPack(
        id="yahoo",
        label="Yahoo Mail",
        imap_host="imap.mail.yahoo.com",
        exclude_folders=("Trash", "Bulk Mail", "Spam", "ready2delete", "Intentionally Kept"),
        auth_help=(
            "Enable IMAP in Yahoo settings, turn on two-step verification, then create an "
            "app password (not your normal Yahoo password)."
        ),
        password_label="Yahoo app password",
    ),
    "zoho": ProviderPack(
        id="zoho",
        label="Zoho Mail",
        imap_host="imap.zoho.com",
        exclude_folders=("Trash", "Spam", "ready2delete", "Intentionally Kept"),
        auth_help=(
            "In Zoho Mail → Settings → Mail Accounts → IMAP Access, enable IMAP and use an "
            "application-specific password if two-factor is on."
        ),
        password_label="Zoho app password",
    ),
    "gmail_imap": ProviderPack(
        id="gmail_imap",
        label="Gmail (IMAP)",
        imap_host="imap.gmail.com",
        trash_folder="[Gmail]/Trash",
        exclude_folders=(
            "[Gmail]/Trash",
            "[Gmail]/Spam",
            "[Gmail]/Drafts",
            "ready2delete",
            "Intentionally Kept",
        ),
        auth_help=(
            "Enable IMAP in Gmail settings. Create a Google App Password (2-Step Verification "
            "required). OAuth API support may come later; this pack uses IMAP."
        ),
        password_label="Google app password",
    ),
    "imap": ProviderPack(
        id="imap",
        label="Other IMAP",
        imap_host="",
        exclude_folders=("Trash", "Spam", "Junk", "ready2delete", "Intentionally Kept"),
        auth_help=(
            "Enter your provider’s IMAP host and an app password or mailbox password as required "
            "by your host."
        ),
        password_label="IMAP password",
    ),
}


def list_provider_packs() -> list[dict]:
    return [
        {
            "id": p.id,
            "label": p.label,
            "imap_host": p.imap_host,
            "imap_port": p.imap_port,
            "imap_ssl": p.imap_ssl,
            "inbox_folder": p.inbox_folder,
            "trash_folder": p.trash_folder,
            "ready_folder": p.ready_folder,
            "kept_folder": p.kept_folder,
            "exclude_folders": list(p.exclude_folders),
            "auth_help": p.auth_help,
            "password_label": p.password_label,
        }
        for p in PACKS.values()
    ]


def get_pack(provider_id: str) -> ProviderPack:
    key = (provider_id or "").lower().strip()
    if key == "gmail":
        key = "gmail_imap"
    if key not in PACKS:
        raise ValueError(f"Unknown provider pack: {provider_id}")
    return PACKS[key]

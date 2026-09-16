"""Profile loading: config.toml + .env credentials."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[2]


def profiles_dir() -> Path:
    """Profile root. Override with MAIL_JANITOR_PROFILES_DIR for isolated deploys."""
    override = os.environ.get("MAIL_JANITOR_PROFILES_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return REPO_ROOT / "profiles"


# Back-compat alias — prefer profiles_dir() so env overrides apply at call time.
PROFILES_DIR = profiles_dir()


@dataclass
class Profile:
    name: str
    path: Path
    provider: str
    email: str
    imap_host: str
    imap_port: int
    imap_ssl: bool
    exclude_folders: list[str] = field(default_factory=list)
    inbox_folder: str = "Inbox"
    kept_folder: str = "Intentionally Kept"
    ready_folder: str = "ready2delete"
    trash_folder: str = "Trash"
    stage_inbox_only: bool = True
    stage_folders: list[str] = field(default_factory=list)
    preview_sample_n: int = 20
    scan_batch_size: int = 500
    move_batch_size: int = 200
    app_password: str = ""

    @property
    def db_path(self) -> Path:
        return self.path / "mail.db"

    @property
    def rules_path(self) -> Path:
        return self.path / "rules.yaml"

    @property
    def audit_path(self) -> Path:
        return self.path / "audit.jsonl"

    @property
    def firewall_path(self) -> Path:
        return self.path / "firewall.yaml"

    @property
    def config_path(self) -> Path:
        return self.path / "config.toml"

    def effective_stage_folders(self) -> list[str] | None:
        """Folders stage/preview rules target when the rule has no explicit folder. None = all."""
        if self.stage_folders:
            return list(self.stage_folders)
        if self.stage_inbox_only:
            return [self.inbox_folder]
        return None

    def stage_scope_label(self, rule_folder: str | None = None) -> str:
        if rule_folder:
            return rule_folder
        folders = self.effective_stage_folders()
        if not folders:
            return "all folders"
        if len(folders) == 1:
            return folders[0]
        return ", ".join(folders)

    def stage_folder_sql(self, rule: Any) -> tuple[str, list[str]]:
        """SQL fragment restricting folder scope for rules without an explicit folder."""
        if rule.folder is not None:
            return "", []
        folders = self.effective_stage_folders()
        if not folders:
            return "", []
        placeholders = ", ".join("?" for _ in folders)
        return f" AND folder IN ({placeholders})", folders


def list_profiles() -> list[str]:
    from mail_janitor.client_sessions import client_mode, current_uid

    root = profiles_dir()
    if not root.exists():
        return []
    if client_mode():
        uid = current_uid()
        if uid and (root / uid / "config.toml").exists():
            return [uid]
        return []
    names = []
    for p in sorted(root.iterdir()):
        if p.is_dir() and not p.name.startswith("_") and not p.name.startswith("."):
            if (p / "config.toml").exists():
                names.append(p.name)
    return names


def load_profile(name: str) -> Profile:
    path = profiles_dir() / name
    if not path.is_dir():
        raise FileNotFoundError(
            f"Profile not found: {name} (expected {path}). "
            f"Copy profiles/_example to profiles/{name} and configure it."
        )
    config_path = path / "config.toml"
    if not config_path.exists():
        raise FileNotFoundError(f"Missing config.toml in {path}")

    with config_path.open("rb") as f:
        raw = tomllib.load(f)

    from mail_janitor.client_sessions import client_mode, load_credentials

    email = ""
    app_password = ""
    if client_mode():
        creds = load_credentials(name)
        if creds:
            email, app_password = creds
        if not email:
            email = str(raw.get("email") or "") or "you@example.com"
        # Empty password allowed until Connect — guide page must render.
    else:
        env_path = path / ".env"
        if env_path.exists():
            load_dotenv(env_path, override=True)
        email = os.getenv("MAIL_JANITOR_EMAIL") or raw.get("email") or ""
        app_password = os.getenv("MAIL_JANITOR_APP_PASSWORD") or ""
        if not email:
            raise ValueError(f"Set email in {config_path} or MAIL_JANITOR_EMAIL in {env_path}")
        if not app_password:
            raise ValueError(
                f"Set MAIL_JANITOR_APP_PASSWORD in {env_path} "
                "(Yahoo app password; never commit .env)"
            )

    return Profile(
        name=name,
        path=path,
        provider=str(raw.get("provider", "yahoo")),
        email=email,
        imap_host=str(raw.get("imap_host", "imap.mail.yahoo.com")),
        imap_port=int(raw.get("imap_port", 993)),
        imap_ssl=bool(raw.get("imap_ssl", True)),
        exclude_folders=list(raw.get("exclude_folders") or []),
        inbox_folder=str(raw.get("inbox_folder", "Inbox")),
        kept_folder=str(raw.get("kept_folder", "Intentionally Kept")),
        ready_folder=str(raw.get("ready_folder", "ready2delete")),
        trash_folder=str(raw.get("trash_folder", "Trash")),
        stage_inbox_only=bool(raw.get("stage_inbox_only", True)),
        stage_folders=[str(f) for f in (raw.get("stage_folders") or [])],
        preview_sample_n=int(raw.get("preview_sample_n", 20)),
        scan_batch_size=int(raw.get("scan_batch_size", 500)),
        move_batch_size=int(raw.get("move_batch_size", 200)),
        app_password=app_password,
    )


def ensure_profile_files(name: str) -> Path:
    """Create a profile directory from _example if missing."""
    safe = _safe_profile_name(name)
    root = profiles_dir()
    dest = root / safe
    example = root / "_example"
    if not example.exists():
        # Demo/personal volume may omit _example — fall back to package template.
        example = REPO_ROOT / "profiles" / "_example"
    dest.mkdir(parents=True, exist_ok=True)
    for fname in ("config.toml", "rules.yaml", "firewall.yaml", ".env.example"):
        src = example / fname
        dst = dest / fname
        if src.exists() and not dst.exists():
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    # Ensure firewall.yaml even if example missing
    fw = dest / "firewall.yaml"
    if not fw.exists():
        from mail_janitor.firewall_policy import default_firewall_yaml

        fw.write_text(default_firewall_yaml(), encoding="utf-8")
    env = dest / ".env"
    if not env.exists() and (dest / ".env.example").exists():
        env.write_text((dest / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    return dest


def _safe_profile_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", (name or "").strip()).strip("-_").lower()
    if not cleaned or cleaned.startswith("_") or cleaned.startswith("."):
        raise ValueError("Choose a simple mailbox name using letters and numbers")
    if cleaned in {"example", "example-profile"}:
        raise ValueError("That name is reserved")
    return cleaned


def create_profile(name: str, *, provider: str = "yahoo") -> dict[str, Any]:
    """Create a new empty profile dir and apply provider defaults."""
    safe = _safe_profile_name(name)
    root = profiles_dir()
    dest = root / safe
    if dest.exists() and (dest / "config.toml").exists():
        raise ValueError(f"Mailbox “{safe}” already exists")
    ensure_profile_files(safe)
    apply_provider_pack(safe, provider)
    return {"ok": True, "profile": safe}


def delete_profile(name: str, *, active: str | None = None) -> dict[str, Any]:
    """Remove a profile directory. Refuses active mailbox and reserved names."""
    import shutil

    safe = _safe_profile_name(name)
    if active and safe == active:
        raise ValueError("Switch to another mailbox before deleting this one")
    path = profiles_dir() / safe
    if not path.is_dir():
        raise FileNotFoundError(f"Mailbox “{safe}” not found")
    shutil.rmtree(path)
    return {"ok": True, "deleted": safe}


def profile_summaries() -> list[dict[str, Any]]:
    """Lightweight list for Mission Control (no secrets)."""
    out: list[dict[str, Any]] = []
    for name in list_profiles():
        path = profiles_dir() / name
        email = ""
        provider = ""
        cfg = path / "config.toml"
        if cfg.exists():
            try:
                with cfg.open("rb") as f:
                    raw = tomllib.load(f)
                email = str(raw.get("email") or "")
                provider = str(raw.get("provider") or "")
            except Exception:
                pass
        env_path = path / ".env"
        if env_path.exists():
            try:
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("MAIL_JANITOR_EMAIL="):
                        email = line.split("=", 1)[1].strip().strip('"').strip("'") or email
                        break
            except Exception:
                pass
        out.append(
            {
                "name": name,
                "email": email,
                "provider": provider,
                "has_db": (path / "mail.db").exists(),
            }
        )
    return out


def _toml_string_list(values: list[str]) -> str:
    parts: list[str] = []
    for value in values:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'"{escaped}"')
    return "[" + ", ".join(parts) + "]"


def _upsert_toml_line(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}\s*=.*$", re.MULTILINE)
    line = f"{key} = {value}"
    if pattern.search(text):
        return pattern.sub(line, text, count=1)
    trimmed = text.rstrip("\n")
    return f"{trimmed}\n{line}\n" if trimmed else f"{line}\n"


def _remove_toml_key(text: str, key: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}\s*=.*\n?", re.MULTILINE)
    return pattern.sub("", text)


def save_stage_folders(profile: Profile, folders: list[str] | None) -> None:
    """Persist cleanup folder scope to config.toml.

    folders=None means all indexed folders (clears stage_folders, stage_inbox_only=false).
    Otherwise writes an explicit stage_folders list (stage_inbox_only is ignored).
    """
    path = profile.config_path
    text = path.read_text(encoding="utf-8")
    if folders is None:
        text = _remove_toml_key(text, "stage_folders")
        text = _upsert_toml_line(text, "stage_inbox_only", "false")
    else:
        cleaned = [f.strip() for f in folders if f and f.strip()]
        if not cleaned:
            raise ValueError("Select at least one folder")
        text = _upsert_toml_line(text, "stage_folders", _toml_string_list(cleaned))
    path.write_text(text, encoding="utf-8")


def apply_provider_pack(profile_name: str, provider_id: str, *, imap_host: str | None = None) -> Path:
    """Ensure profile exists and apply provider pack defaults to config.toml."""
    from mail_janitor.providers.packs import get_pack

    path = ensure_profile_files(profile_name)
    pack = get_pack(provider_id)
    host = (imap_host or pack.imap_host or "").strip()
    if not host and pack.id == "imap":
        raise ValueError("IMAP host is required for Other IMAP")
    cfg = path / "config.toml"
    text = cfg.read_text(encoding="utf-8") if cfg.exists() else ""
    text = _upsert_toml_line(text, "provider", f'"{pack.id if pack.id != "gmail" else "gmail_imap"}"')
    if host:
        text = _upsert_toml_line(text, "imap_host", f'"{host}"')
    text = _upsert_toml_line(text, "imap_port", str(pack.imap_port))
    text = _upsert_toml_line(text, "imap_ssl", "true" if pack.imap_ssl else "false")
    text = _upsert_toml_line(text, "inbox_folder", f'"{pack.inbox_folder}"')
    text = _upsert_toml_line(text, "trash_folder", f'"{pack.trash_folder}"')
    text = _upsert_toml_line(text, "ready_folder", f'"{pack.ready_folder}"')
    text = _upsert_toml_line(text, "kept_folder", f'"{pack.kept_folder}"')
    text = _upsert_toml_line(text, "exclude_folders", _toml_string_list(list(pack.exclude_folders)))
    text = _upsert_toml_line(text, "stage_inbox_only", "true")
    cfg.write_text(text, encoding="utf-8")
    return path


def write_profile_credentials(profile_name: str, email: str, app_password: str) -> None:
    """Store MAIL_JANITOR_* credentials for a profile.

    Personal mode writes profiles/<name>/.env.
    Client mode stores memory + wipeable .session-secrets only (never durable .env).
    """
    from mail_janitor.client_sessions import client_mode, store_credentials

    email = email.strip()
    app_password = app_password.strip()
    if not email or "@" not in email:
        raise ValueError("Enter a valid email address")
    if not app_password:
        raise ValueError("App password is required")

    if client_mode():
        store_credentials(profile_name, email, app_password)
        return

    path = ensure_profile_files(profile_name)
    env_path = path / ".env"
    lines = [
        f"MAIL_JANITOR_EMAIL={email}",
        f"MAIL_JANITOR_APP_PASSWORD={app_password}",
        "",
    ]
    env_path.write_text("\n".join(lines), encoding="utf-8")
    cfg = path / "config.toml"
    if cfg.exists():
        text = cfg.read_text(encoding="utf-8")
        text = _upsert_toml_line(text, "email", f'"{email}"')
        cfg.write_text(text, encoding="utf-8")


def test_imap_connection(profile: Profile) -> dict:
    """Select Inbox and return folder names — used by guided Connect step."""
    from mail_janitor.providers import get_provider

    provider = get_provider(profile.provider)
    client = provider.connect(profile)
    try:
        folders = [f.name for f in client.list_folders()]
        client.select(profile.inbox_folder, readonly=True)
        return {
            "ok": True,
            "email": profile.email,
            "provider": profile.provider,
            "folder_count": len(folders),
            "folders": folders[:40],
            "inbox_folder": profile.inbox_folder,
        }
    finally:
        client.close()

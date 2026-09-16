"""CLI entrypoints for mail-janitor."""

from __future__ import annotations

import json

import click

from mail_janitor import __version__
from mail_janitor.apply import (
    CONFIRM_KEPT,
    CONFIRM_READY,
    CONFIRM_TRASH,
    CONFIRM_UNDO,
    CONFIRM_UNDO_KEPT,
    apply_to_kept,
    apply_to_ready,
    list_moves,
    preflight_kept_inbox,
    preflight_staged,
    ready_to_trash,
    undo_from_kept,
    undo_from_ready,
)
from mail_janitor.config import ensure_profile_files, list_profiles, load_profile
from mail_janitor.discover import discover, preview_all_stage_rules, preview_rule
from mail_janitor.rules import load_rules
from mail_janitor.scan import backfill_list_unsubscribe, refresh_blank_headers, scan_mailbox
from mail_janitor.stage import clear_staged, stage_rules


def _print_json(data) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


@click.group()
@click.version_option(__version__, prog_name="mail-janitor")
def main() -> None:
    """Safe bulk mail cleanup — headers-first, review before move."""


@main.command("profiles")
def profiles_cmd() -> None:
    """List configured profiles."""
    names = list_profiles()
    if not names:
        click.echo("No profiles yet. Run: mail-janitor init-profile <name>")
        return
    for n in names:
        click.echo(n)


@main.command("init-profile")
@click.argument("name")
def init_profile_cmd(name: str) -> None:
    """Create a profile directory from the example template."""
    path = ensure_profile_files(name)
    click.echo(f"Created {path}")
    click.echo(f"Edit {path / 'config.toml'} and {path / '.env'} (app password), then: mail-janitor scan -p {name}")


@main.command("scan")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--no-resume", is_flag=True, help="Rescan from UID 0 in each folder")
def scan_cmd(profile_name: str, no_resume: bool) -> None:
    """Headers-only IMAP scan into the profile SQLite index."""
    profile = load_profile(profile_name)
    click.echo(f"Scanning {profile.email} ({profile.provider})…")
    stats = scan_mailbox(profile, resume=not no_resume)
    _print_json(stats)


@main.command("backfill-list-unsubscribe")
@click.option("-p", "--profile", "profile_name", required=True)
def backfill_list_unsubscribe_cmd(profile_name: str) -> None:
    """Repair list_unsubscribe flags by re-fetching full HEADER for indexed UIDs."""
    profile = load_profile(profile_name)
    click.echo(f"Backfilling List-Unsubscribe for {profile.email}…")
    stats = backfill_list_unsubscribe(profile)
    _print_json(stats)


@main.command("refresh-blank-headers")
@click.option("-p", "--profile", "profile_name", required=True)
def refresh_blank_headers_cmd(profile_name: str) -> None:
    """Re-fetch From/Subject/Date for indexed rows that came back blank from scan."""
    profile = load_profile(profile_name)
    click.echo(f"Refreshing blank headers for {profile.email}…")
    stats = refresh_blank_headers(profile)
    _print_json(stats)


@main.command("archive-dormant-stage")
@click.option("-p", "--profile", "profile_name", required=True)
def archive_dormant_cmd(profile_name: str) -> None:
    """Mark active stage rules with 0 current matches as inactive (faster staging)."""
    from mail_janitor.rules import archive_dormant_stage_rules

    _print_json(archive_dormant_stage_rules(load_profile(profile_name)))


@main.command("discover")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--top", default=30, show_default=True)
def discover_cmd(profile_name: str, top: int) -> None:
    """Print mailbox aggregates from the local header index."""
    profile = load_profile(profile_name)
    _print_json(discover(profile, top_n=top))


@main.command("preview")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--rule", "rule_id", default=None, help="Stage rule id; omit to preview all")
def preview_cmd(profile_name: str, rule_id: str | None) -> None:
    """Metadata-only preview for stage rule(s)."""
    profile = load_profile(profile_name)
    if rule_id:
        ruleset = load_rules(profile.rules_path)
        rule = ruleset.get_stage_rule(rule_id)
        if not rule:
            raise click.ClickException(f"Unknown stage rule: {rule_id}")
        _print_json(preview_rule(profile, rule))
    else:
        _print_json(preview_all_stage_rules(profile))


@main.command("stage")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--rule", "rule_ids", multiple=True, help="Limit to rule id(s)")
@click.option("--clear", is_flag=True, help="Clear staged table before staging")
def stage_cmd(profile_name: str, rule_ids: tuple[str, ...], clear: bool) -> None:
    """Stage rule matches for review (no mailbox changes)."""
    profile = load_profile(profile_name)
    result = stage_rules(profile, rule_ids=list(rule_ids) or None, clear=clear)
    _print_json(result)


@main.command("clear-staged")
@click.option("-p", "--profile", "profile_name", required=True)
@click.confirmation_option(prompt="Clear all staged rows?")
def clear_staged_cmd(profile_name: str) -> None:
    clear_staged(load_profile(profile_name))
    click.echo("Cleared.")


@main.command("preflight")
@click.option("-p", "--profile", "profile_name", required=True)
def preflight_cmd(profile_name: str) -> None:
    """Show what apply would move (included staged only)."""
    _print_json(preflight_staged(load_profile(profile_name)))


@main.command("preflight-kept")
@click.option("-p", "--profile", "profile_name", required=True)
def preflight_kept_cmd(profile_name: str) -> None:
    """Show Inbox messages matching keep rules (apply-kept candidates)."""
    _print_json(preflight_kept_inbox(load_profile(profile_name)))


@main.command("apply-kept")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--confirm", required=True, help=f'Must be exactly "{CONFIRM_KEPT}"')
@click.option("--limit", type=int, default=None)
def apply_kept_cmd(profile_name: str, confirm: str, limit: int | None) -> None:
    """Move Inbox keep-rule matches to the intentionally kept folder."""
    profile = load_profile(profile_name)
    click.echo("Preflight:")
    _print_json(preflight_kept_inbox(profile))
    result = apply_to_kept(profile, confirm=confirm, limit=limit)
    _print_json(result)


@main.command("apply")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--confirm", required=True, help=f'Must be exactly "{CONFIRM_READY}"')
@click.option("--limit", type=int, default=None)
def apply_cmd(profile_name: str, confirm: str, limit: int | None) -> None:
    """Move included staged messages to ready2delete."""
    profile = load_profile(profile_name)
    click.echo("Preflight:")
    _print_json(preflight_staged(profile))
    result = apply_to_ready(profile, confirm=confirm, limit=limit)
    _print_json(result)


@main.command("undo")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--confirm", required=True, help=f'Must be exactly "{CONFIRM_UNDO}"')
@click.option("--limit", type=int, default=None)
def undo_cmd(profile_name: str, confirm: str, limit: int | None) -> None:
    """Move messages from ready2delete back to original folders."""
    result = undo_from_ready(load_profile(profile_name), confirm=confirm, limit=limit)
    _print_json(result)


@main.command("undo-kept")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--confirm", required=True, help=f'Must be exactly "{CONFIRM_UNDO_KEPT}"')
@click.option("--limit", type=int, default=None)
def undo_kept_cmd(profile_name: str, confirm: str, limit: int | None) -> None:
    """Move messages from the kept folder back to Inbox."""
    result = undo_from_kept(load_profile(profile_name), confirm=confirm, limit=limit)
    _print_json(result)


@main.command("to-trash")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--confirm", required=True, help=f'Must be exactly "{CONFIRM_TRASH}"')
@click.option("--batch-size", default=100, show_default=True)
def to_trash_cmd(profile_name: str, confirm: str, batch_size: int) -> None:
    """Move a batch from ready2delete to Trash (Yahoo: 7-day auto-purge)."""
    click.echo(
        "WARNING: Yahoo Trash empties after 7 days and you cannot change that.",
        err=True,
    )
    result = ready_to_trash(load_profile(profile_name), confirm=confirm, batch_size=batch_size)
    _print_json(result)


@main.command("moves")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--all", "show_all", is_flag=True, help="Include undone moves")
def moves_cmd(profile_name: str, show_all: bool) -> None:
    _print_json(list_moves(load_profile(profile_name), undone_only=not show_all))


@main.command("review")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8787, show_default=True, type=int)
def review_cmd(profile_name: str, host: str, port: int) -> None:
    """Start the local review UI (metadata list; body on Open only)."""
    from mail_janitor.client_sessions import client_mode

    if not client_mode():
        # Validate profile loads (credentials present) before binding port
        load_profile(profile_name)
    from mail_janitor.web.app import run_server

    click.echo(f"Review UI: http://{host}:{port}/  (Ctrl+C to stop)")
    run_server(profile_name, host=host, port=port)


@main.command("rules-show")
@click.option("-p", "--profile", "profile_name", required=True)
def rules_show_cmd(profile_name: str) -> None:
    profile = load_profile(profile_name)
    ruleset = load_rules(profile.rules_path)
    _print_json(
        {
            "keep": [r.raw for r in ruleset.keep],
            "stage": [r.raw for r in ruleset.stage],
            "path": str(profile.rules_path),
        }
    )


@main.group("firewall")
def firewall_group() -> None:
    """Inbound firewall: quarantine (not Trash), allow/block, release."""


@firewall_group.command("status")
@click.option("-p", "--profile", "profile_name", required=True)
def firewall_status_cmd(profile_name: str) -> None:
    from mail_janitor.firewall import firewall_status

    _print_json(firewall_status(load_profile(profile_name)))


@firewall_group.command("once")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--dry-run", is_flag=True, help="Evaluate only; do not move")
def firewall_once_cmd(profile_name: str, dry_run: bool) -> None:
    """Process new Inbox mail since the firewall watermark (one pass)."""
    from mail_janitor.firewall import process_once

    _print_json(process_once(load_profile(profile_name), dry_run=dry_run))


@firewall_group.command("watch")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--dry-run", is_flag=True)
def firewall_watch_cmd(profile_name: str, dry_run: bool) -> None:
    """Poll forever for new mail and quarantine matches. Ctrl+C to stop."""
    from mail_janitor.firewall import firewall_path, process_once
    from mail_janitor.firewall_policy import load_firewall

    profile = load_profile(profile_name)
    cfg = load_firewall(firewall_path(profile))
    click.echo(
        f"Firewall watching {cfg.watch_folder} → {cfg.quarantine_folder} "
        f"every {cfg.poll_seconds}s (heuristic={cfg.heuristic_quarantine}). Ctrl+C to stop."
    )
    import time

    try:
        while True:
            result = process_once(profile, dry_run=dry_run)
            _print_json(result)
            if dry_run:
                break
            time.sleep(cfg.poll_seconds)
    except KeyboardInterrupt:
        click.echo("Stopped.")


@firewall_group.command("list")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--limit", default=50, show_default=True)
def firewall_list_cmd(profile_name: str, limit: int) -> None:
    """List held quarantine actions (not yet released)."""
    from mail_janitor.firewall import list_quarantine

    _print_json(list_quarantine(load_profile(profile_name), limit=limit))


@firewall_group.command("allow")
@click.option("-p", "--profile", "profile_name", required=True)
@click.argument("from_addr")
def firewall_allow_cmd(profile_name: str, from_addr: str) -> None:
    """Always leave this sender in Inbox (and remove from block list)."""
    from mail_janitor.firewall_policy import add_allow_sender

    profile = load_profile(profile_name)
    rule = add_allow_sender(profile.firewall_path, from_addr)
    _print_json({"ok": True, "rule_id": rule.id, "from_address": rule.from_address})


@firewall_group.command("block")
@click.option("-p", "--profile", "profile_name", required=True)
@click.argument("target")
@click.option("--domain", is_flag=True, help="Treat TARGET as a from_domain")
def firewall_block_cmd(profile_name: str, target: str, domain: bool) -> None:
    """Quarantine future mail from this sender (or domain with --domain)."""
    from mail_janitor.firewall_policy import add_block_domain, add_block_sender

    profile = load_profile(profile_name)
    if domain:
        rule = add_block_domain(profile.firewall_path, target)
    else:
        rule = add_block_sender(profile.firewall_path, target)
    _print_json(
        {
            "ok": True,
            "rule_id": rule.id,
            "from_address": rule.from_address,
            "from_domain": rule.from_domain,
        }
    )


@firewall_group.command("release")
@click.option("-p", "--profile", "profile_name", required=True)
@click.option("--id", "action_id", type=int, multiple=True, help="firewall_actions id(s)")
@click.option("--limit", type=int, default=None, help="Release oldest N held items")
def firewall_release_cmd(
    profile_name: str, action_id: tuple[int, ...], limit: int | None
) -> None:
    """Restore quarantined mail back to Inbox."""
    from mail_janitor.firewall import release_quarantine

    ids = list(action_id) or None
    if not ids and limit is None:
        raise click.UsageError("Pass --id and/or --limit")
    _print_json(
        release_quarantine(load_profile(profile_name), action_ids=ids, limit=limit)
    )


if __name__ == "__main__":
    main()

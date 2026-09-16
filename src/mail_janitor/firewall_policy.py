"""Inbound email firewall — quarantine (not Trash), allow/block, recoverable."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mail_janitor.heuristics import marketing_ish_domain
from mail_janitor.rules import Rule, _slug


@dataclass
class FirewallConfig:
    enabled: bool = True
    watch_folder: str = "Inbox"
    quarantine_folder: str = "quarantine"
    poll_seconds: int = 60
    heuristic_quarantine: bool = False  # off by default — start with explicit block list
    high_volume_min: int = 1  # unused for single-message eval; kept for config symmetry
    allow: list[Rule] = field(default_factory=list)
    block: list[Rule] = field(default_factory=list)
    path: Path | None = None


def default_firewall_yaml() -> str:
    return """# Inbound firewall — never auto-Trash.
# Order: allow wins → block quarantines → optional heuristic → pass (leave in Inbox).

enabled: true
watch_folder: Inbox
quarantine_folder: quarantine
poll_seconds: 60

# Soft auto-quarantine from header heuristics (list-unsub / marketing-ish hosts).
# Keep false until you've seeded allow rules for people you know.
heuristic_quarantine: false

allow: []
# - id: allow-alice
#   from_address: alice@example.com

block: []
# - id: block-spam-domain
#   from_domain: messenger.tanga.com
"""


def load_firewall(path: Path) -> FirewallConfig:
    if not path.exists():
        path.write_text(default_firewall_yaml(), encoding="utf-8")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    allow = [Rule.from_dict(r, "keep") for r in (data.get("allow") or [])]
    block = [Rule.from_dict(r, "stage") for r in (data.get("block") or [])]
    return FirewallConfig(
        enabled=bool(data.get("enabled", True)),
        watch_folder=str(data.get("watch_folder") or "Inbox"),
        quarantine_folder=str(data.get("quarantine_folder") or "quarantine"),
        poll_seconds=max(15, int(data.get("poll_seconds") or 60)),
        heuristic_quarantine=bool(data.get("heuristic_quarantine", False)),
        high_volume_min=int(data.get("high_volume_min") or 1),
        allow=allow,
        block=block,
        path=path,
    )


def save_firewall(cfg: FirewallConfig) -> None:
    if cfg.path is None:
        raise ValueError("FirewallConfig.path is required to save")
    data = {
        "enabled": cfg.enabled,
        "watch_folder": cfg.watch_folder,
        "quarantine_folder": cfg.quarantine_folder,
        "poll_seconds": cfg.poll_seconds,
        "heuristic_quarantine": cfg.heuristic_quarantine,
        "allow": [_rule_yaml(r) for r in cfg.allow],
        "block": [_rule_yaml(r) for r in cfg.block],
    }
    cfg.path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _rule_yaml(rule: Rule) -> dict[str, Any]:
    out: dict[str, Any] = {"id": rule.id}
    if rule.label and rule.label != rule.id:
        out["label"] = rule.label
    for key in (
        "from_domain",
        "from_address",
        "subject_contains",
        "older_than_days",
        "folder",
        "has_list_unsubscribe",
        "min_size",
        "match",
    ):
        val = getattr(rule, key)
        if val is not None and not (key == "match" and val == "all"):
            out[key] = val
    return out


def _message_matches_rule(msg: dict[str, Any], rule: Rule) -> bool:
    """In-memory match (single message) — mirrors rule_sql_clauses semantics."""
    clauses_hit: list[bool] = []
    if rule.from_domain is not None:
        clauses_hit.append((msg.get("from_domain") or "").lower() == rule.from_domain)
    if rule.from_address is not None:
        clauses_hit.append((msg.get("from_addr") or "").lower() == rule.from_address)
    if rule.subject_contains is not None:
        sub = (msg.get("subject") or "").lower()
        clauses_hit.append(rule.subject_contains.lower() in sub)
    if rule.has_list_unsubscribe is not None:
        want = 1 if rule.has_list_unsubscribe else 0
        clauses_hit.append(int(msg.get("list_unsubscribe") or 0) == want)
    if rule.min_size is not None:
        clauses_hit.append(int(msg.get("size") or 0) >= rule.min_size)
    if rule.folder is not None:
        clauses_hit.append(msg.get("folder") == rule.folder)
    # older_than_days ignored for brand-new inbound mail
    if not clauses_hit:
        return False
    if rule.match == "any":
        return any(clauses_hit)
    return all(clauses_hit)


@dataclass
class Decision:
    action: str  # pass | quarantine
    reason: str
    rule_id: str | None = None
    flags: list[str] = field(default_factory=list)


def evaluate_message(msg: dict[str, Any], cfg: FirewallConfig) -> Decision:
    """
    Decide what to do with one inbound message.
    Never returns trash/delete — only pass or quarantine.
    """
    for rule in cfg.allow:
        if _message_matches_rule(msg, rule):
            return Decision("pass", f"allow:{rule.id}", rule_id=rule.id)

    for rule in cfg.block:
        if _message_matches_rule(msg, rule):
            return Decision("quarantine", f"block:{rule.id}", rule_id=rule.id)

    if cfg.heuristic_quarantine:
        flags: list[str] = []
        if int(msg.get("list_unsubscribe") or 0) == 1:
            flags.append("list-unsub")
        if marketing_ish_domain(msg.get("from_domain")):
            flags.append("marketing-ish")
        if flags:
            return Decision(
                "quarantine",
                "heuristic:" + ",".join(flags),
                rule_id=None,
                flags=flags,
            )

    return Decision("pass", "default_pass")


def add_allow_sender(path: Path, from_addr: str) -> Rule:
    cfg = load_firewall(path)
    addr = from_addr.lower().strip()
    for r in cfg.allow:
        if r.from_address == addr:
            return r
    # Remove from block if present
    cfg.block = [r for r in cfg.block if r.from_address != addr]
    rule = Rule(
        id=_slug(addr, "allow"),
        label=f"Allow {addr}",
        from_address=addr,
        action="keep",
    )
    cfg.allow.append(rule)
    save_firewall(cfg)
    return rule


def add_block_sender(path: Path, from_addr: str) -> Rule:
    cfg = load_firewall(path)
    addr = from_addr.lower().strip()
    for r in cfg.block:
        if r.from_address == addr:
            return r
    cfg.allow = [r for r in cfg.allow if r.from_address != addr]
    rule = Rule(
        id=_slug(addr, "block"),
        label=f"Block {addr}",
        from_address=addr,
        action="stage",
    )
    cfg.block.append(rule)
    save_firewall(cfg)
    return rule


def add_block_domain(path: Path, domain: str) -> Rule:
    cfg = load_firewall(path)
    domain = domain.lower().strip()
    for r in cfg.block:
        if r.from_domain == domain and not r.from_address:
            return r
    rule = Rule(
        id=_slug(domain, "block-domain"),
        label=f"Block domain {domain}",
        from_domain=domain,
        action="stage",
    )
    cfg.block.append(rule)
    save_firewall(cfg)
    return rule

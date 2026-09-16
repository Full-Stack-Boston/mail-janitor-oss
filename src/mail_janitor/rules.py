"""YAML rule engine — keep rules always win; stage rules mark candidates."""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

RESET_KEEP_PHRASE = "RESET ALL KEEP RULES"
RESET_STAGE_PHRASE = "RESET ALL STAGE RULES"


# From local-parts that usually indicate automated / bulk mail, not a person.
BUSINESS_FROM_PREFIXES: tuple[str, ...] = (
    "noreply@",
    "no-reply@",
    "donotreply@",
    "do-not-reply@",
    "info@",
    "notifications@",
    "notification@",
    "newsletter@",
    "marketing@",
    "mailer-daemon@",
    "postmaster@",
    "bounce@",
    "bounces@",
    "alert@",
    "alerts@",
    "updates@",
    "update@",
    "news@",
    "deals@",
    "offers@",
    "team@",
    "hello@",
    "contact@",
    "sales@",
    "support@",
)


@dataclass
class Rule:
    id: str
    label: str = ""
    from_domain: str | None = None
    from_domain_suffix: str | None = None
    from_address: str | None = None
    from_address_prefixes: list[str] = field(default_factory=list)
    subject_contains: str | None = None
    older_than_days: int | None = None
    folder: str | None = None
    has_list_unsubscribe: bool | None = None
    min_size: int | None = None
    match: str = "all"  # all = AND, any = OR
    action: str = "stage"
    active: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], default_action: str) -> "Rule":
        if "id" not in data:
            raise ValueError(f"Rule missing id: {data}")
        return cls(
            id=str(data["id"]),
            label=str(data.get("label") or data["id"]),
            from_domain=_lower_or_none(data.get("from_domain")),
            from_domain_suffix=_normalize_suffix_or_none(data.get("from_domain_suffix")),
            from_address=_lower_or_none(data.get("from_address")),
            from_address_prefixes=_prefixes_from_dict(data),
            subject_contains=data.get("subject_contains"),
            older_than_days=_int_or_none(data.get("older_than_days")),
            folder=data.get("folder"),
            has_list_unsubscribe=_bool_or_none(data.get("has_list_unsubscribe")),
            min_size=_int_or_none(data.get("min_size")),
            match=str(data.get("match") or "all").lower(),
            action=str(data.get("action") or default_action),
            active=bool(data.get("active", True)),
            raw=data,
        )


@dataclass
class RuleSet:
    keep: list[Rule] = field(default_factory=list)
    stage: list[Rule] = field(default_factory=list)

    def get_stage_rule(self, rule_id: str) -> Rule | None:
        for r in self.stage:
            if r.id == rule_id:
                return r
        return None


def _lower_or_none(v: Any) -> str | None:
    if v is None:
        return None
    return str(v).lower()


def _normalize_suffix_or_none(v: Any) -> str | None:
    if v is None or v == "":
        return None
    s = str(v).strip().lower()
    if not s.startswith("."):
        s = "." + s
    return s


def _normalize_addr_prefix(v: str) -> str:
    """Normalize to lowercase local-part prefix ending with @ (e.g. noreply@)."""
    s = str(v).strip().lower()
    if not s:
        raise ValueError("empty from address prefix")
    if "@" in s:
        local, _domain = s.split("@", 1)
        s = f"{local}@"
    else:
        s = f"{s}@"
    return s


def _prefixes_from_dict(data: dict[str, Any]) -> list[str]:
    raw = list(data.get("from_address_prefixes") or [])
    single = data.get("from_address_prefix")
    if single:
        raw.insert(0, single)
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        p = _normalize_addr_prefix(str(item))
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _int_or_none(v: Any) -> int | None:
    if v is None or v == "":
        return None
    return int(v)


def _bool_or_none(v: Any) -> bool | None:
    if v is None or v == "":
        return None
    return bool(v)


def load_rules(path: Path) -> RuleSet:
    if not path.exists():
        return RuleSet()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    keep = [Rule.from_dict(r, "keep") for r in (data.get("keep") or [])]
    stage = [Rule.from_dict(r, "stage") for r in (data.get("stage") or [])]
    return RuleSet(keep=keep, stage=stage)


def save_rules(path: Path, ruleset: RuleSet) -> None:
    data = {
        "keep": [_rule_to_yaml(r) for r in ruleset.keep],
        "stage": [_rule_to_yaml(r) for r in ruleset.stage],
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _rule_to_yaml(rule: Rule) -> dict[str, Any]:
    out: dict[str, Any] = {"id": rule.id}
    if rule.label and rule.label != rule.id:
        out["label"] = rule.label
    for key in (
        "from_domain",
        "from_domain_suffix",
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
    if rule.from_address_prefixes:
        out["from_address_prefixes"] = list(rule.from_address_prefixes)
    if not rule.active:
        out["active"] = False
    return out


def active_stage_rules(ruleset: RuleSet) -> list[Rule]:
    """Stage rules that are still active (not archived dormant)."""
    return [r for r in ruleset.stage if r.active]


def rule_sql_clauses(rule: Rule, now_ts: int) -> tuple[str, list[Any]]:
    """Build SQL WHERE fragments for a single rule (no keep exclusion).

    from_addr / from_domain are stored lowercase in the index; compare with
    equality so SQLite can use idx_messages_from_addr / idx_messages_from_domain.
    Wrapping columns in lower() forces full scans and made suggestions crawl
    once there were thousands of stage rules.
    """
    clauses: list[str] = []
    params: list[Any] = []

    if rule.from_domain is not None:
        clauses.append("from_domain = ?")
        params.append(rule.from_domain)
    if rule.from_domain_suffix is not None:
        clauses.append("from_domain LIKE ?")
        params.append(f"%{rule.from_domain_suffix}")
    if rule.from_address is not None:
        clauses.append("from_addr = ?")
        params.append(rule.from_address)
    for prefix in rule.from_address_prefixes:
        clauses.append("from_addr LIKE ?")
        params.append(f"{prefix}%")
    if rule.subject_contains is not None:
        clauses.append("lower(subject) LIKE ?")
        params.append(f"%{rule.subject_contains.lower()}%")
    if rule.older_than_days is not None:
        cutoff = now_ts - (rule.older_than_days * 86400)
        # Include undated messages — matches Insights broader_options preview.
        # Unknown age is treated as eligible for age-based cleanup, not excluded.
        clauses.append("(date_ts IS NULL OR date_ts < ?)")
        params.append(cutoff)
    if rule.folder is not None:
        clauses.append("folder = ?")
        params.append(rule.folder)
    if rule.has_list_unsubscribe is not None:
        clauses.append("list_unsubscribe = ?")
        params.append(1 if rule.has_list_unsubscribe else 0)
    if rule.min_size is not None:
        clauses.append("size >= ?")
        params.append(rule.min_size)

    if not clauses:
        return "0", []  # match nothing if empty rule

    joiner = " OR " if rule.match == "any" else " AND "
    return f"({joiner.join(clauses)})", params


def keep_exclusion_sql(ruleset: RuleSet, now_ts: int) -> tuple[str, list[Any]]:
    """Exclude rows matching any keep rule.

    Address/domain-only keeps (the common case) compile to NOT IN lists that
    still use indexes. Mixed/complex keep rules fall back to OR of clauses.
    """
    if not ruleset.keep:
        return "1", []

    addrs: list[str] = []
    domains: list[str] = []
    suffixes: list[str] = []
    complex_parts: list[str] = []
    complex_params: list[Any] = []

    for rule in ruleset.keep:
        simple_addr = (
            rule.from_address is not None
            and rule.from_domain is None
            and rule.from_domain_suffix is None
            and rule.subject_contains is None
            and rule.older_than_days is None
            and rule.folder is None
            and rule.has_list_unsubscribe is None
            and rule.min_size is None
        )
        simple_domain = (
            rule.from_domain is not None
            and rule.from_domain_suffix is None
            and rule.from_address is None
            and rule.subject_contains is None
            and rule.older_than_days is None
            and rule.folder is None
            and rule.has_list_unsubscribe is None
            and rule.min_size is None
        )
        simple_suffix = (
            rule.from_domain_suffix is not None
            and rule.from_domain is None
            and rule.from_address is None
            and rule.subject_contains is None
            and rule.older_than_days is None
            and rule.folder is None
            and rule.has_list_unsubscribe is None
            and rule.min_size is None
        )
        if simple_addr:
            addrs.append(rule.from_address)  # type: ignore[arg-type]
            continue
        if simple_domain:
            domains.append(rule.from_domain)  # type: ignore[arg-type]
            continue
        if simple_suffix:
            suffixes.append(rule.from_domain_suffix)  # type: ignore[arg-type]
            continue
        clause, p = rule_sql_clauses(rule, now_ts)
        if clause == "0":
            continue
        complex_parts.append(clause)
        complex_params.extend(p)

    parts: list[str] = []
    params: list[Any] = []
    if addrs:
        placeholders = ", ".join("?" for _ in addrs)
        parts.append(f"from_addr IN ({placeholders})")
        params.extend(addrs)
    if domains:
        placeholders = ", ".join("?" for _ in domains)
        parts.append(f"from_domain IN ({placeholders})")
        params.extend(domains)
    for suf in suffixes:
        parts.append("from_domain LIKE ?")
        params.append(f"%{suf}")
    parts.extend(complex_parts)
    params.extend(complex_params)
    if not parts:
        return "1", []
    return f"NOT ({' OR '.join(parts)})", params


def add_keep_sender(path: Path, from_addr: str, rule_id: str | None = None) -> Rule:
    return add_keep_rule(
        path,
        {
            "id": rule_id or _slug(from_addr, "keep"),
            "label": f"Keep {from_addr.lower().strip()}",
            "from_address": from_addr.lower().strip(),
        },
    )


def add_keep_domain_suffix(path: Path, suffix: str, rule_id: str | None = None) -> Rule:
    suf = _normalize_suffix_or_none(suffix)
    if not suf:
        raise ValueError("domain suffix required")
    slug = suf.lstrip(".")
    return add_keep_rule(
        path,
        {
            "id": rule_id or f"keep-suffix-{slug}",
            "label": f"Keep *{suf} domains",
            "from_domain_suffix": suf,
        },
    )


def add_keep_rule(path: Path, data: dict[str, Any]) -> Rule:
    """Create/replace a keep rule; drop overlapping stage rules for the same criteria."""
    ruleset = load_rules(path)
    rule = Rule.from_dict({**data, "action": "keep"}, "keep")
    ruleset.keep = [r for r in ruleset.keep if r.id != rule.id]
    # Also replace keep rules with identical primary criteria
    ruleset.keep = [
        r
        for r in ruleset.keep
        if not _same_primary_criteria(r, rule)
    ]
    ruleset.keep.append(rule)
    # Stage rules for the same sender/domain/folder would fight the keep — remove them
    ruleset.stage = [r for r in ruleset.stage if not _same_primary_criteria(r, rule)]
    save_rules(path, ruleset)
    return rule


def delete_keep_rule(path: Path, rule_id: str) -> bool:
    ruleset = load_rules(path)
    before = len(ruleset.keep)
    ruleset.keep = [r for r in ruleset.keep if r.id != rule_id]
    if len(ruleset.keep) == before:
        return False
    save_rules(path, ruleset)
    return True


def backup_rules(path: Path) -> Path:
    """Copy rules.yaml to a timestamped .bak alongside it."""
    if not path.exists():
        raise FileNotFoundError(path)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = path.with_name(f"{path.name}.bak.{ts}")
    shutil.copy2(path, dest)
    return dest


def clear_all_keep_rules(path: Path, *, backup: bool = True) -> dict[str, Any]:
    ruleset = load_rules(path)
    n = len(ruleset.keep)
    bak = backup_rules(path) if backup and n else None
    ruleset.keep = []
    save_rules(path, ruleset)
    return {"removed": n, "backup": str(bak) if bak else None}


def clear_all_stage_rules(path: Path, *, backup: bool = True) -> dict[str, Any]:
    ruleset = load_rules(path)
    n = len(ruleset.stage)
    bak = backup_rules(path) if backup and n else None
    ruleset.stage = []
    save_rules(path, ruleset)
    return {"removed": n, "backup": str(bak) if bak else None}


def _same_primary_criteria(a: Rule, b: Rule) -> bool:
    """True if both target the same address, domain, or folder (single-criterion keep)."""
    if a.from_address and b.from_address and a.from_address == b.from_address:
        return True
    if a.from_domain and b.from_domain and a.from_domain == b.from_domain:
        return True
    if (
        a.from_domain_suffix
        and b.from_domain_suffix
        and a.from_domain_suffix == b.from_domain_suffix
    ):
        return True
    if a.folder and b.folder and a.folder == b.folder:
        return True
    return False


def preview_business_prefix_matches(path: Path, db_path: Path) -> dict[str, Any]:
    """Count messages matching generic business From prefixes (not yet kept)."""
    import time

    from mail_janitor.db import init_db

    rule = Rule(
        id="preview",
        label="preview",
        from_address_prefixes=list(BUSINESS_FROM_PREFIXES),
        match="any",
        action="stage",
    )
    ruleset = load_rules(path)
    now_ts = int(time.time())
    where, params = rule_sql_clauses(rule, now_ts)
    keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
    conn = init_db(db_path)
    row = conn.execute(
        f"""
        SELECT COUNT(*) AS cnt, COALESCE(SUM(size),0) AS bytes
        FROM messages
        WHERE ({where}) AND ({keep_sql})
        """,
        params + keep_params,
    ).fetchone()
    conn.close()
    from mail_janitor.parse_headers import format_size

    return {
        "prefix_count": len(BUSINESS_FROM_PREFIXES),
        "match_count": int(row["cnt"] or 0),
        "total_bytes": int(row["bytes"] or 0),
        "total_bytes_human": format_size(row["bytes"]),
        "prefixes": list(BUSINESS_FROM_PREFIXES),
    }


def add_stage_business_prefix_rule(path: Path, rule_id: str = "generic-business-from") -> Rule:
    """Stage rule: From starts with noreply@, info@, and other bulk-mail prefixes."""
    return add_stage_rule(
        path,
        {
            "id": rule_id,
            "label": "Generic business From (noreply@, info@, …)",
            "match": "any",
            "from_address_prefixes": list(BUSINESS_FROM_PREFIXES),
        },
    )


def add_stage_rule(path: Path, data: dict[str, Any]) -> Rule:
    ruleset = load_rules(path)
    rule = Rule.from_dict(data, "stage")
    # Replace if same id
    ruleset.stage = [r for r in ruleset.stage if r.id != rule.id]
    ruleset.stage.append(rule)
    save_rules(path, ruleset)
    return rule


def update_stage_rule(path: Path, rule_id: str, updates: dict[str, Any]) -> Rule:
    ruleset = load_rules(path)
    rule = ruleset.get_stage_rule(rule_id)
    if not rule:
        raise ValueError(f"Unknown stage rule: {rule_id}")
    data = _rule_to_yaml(rule)
    for key in (
        "label",
        "from_domain",
        "from_domain_suffix",
        "from_address",
        "subject_contains",
        "older_than_days",
        "folder",
        "has_list_unsubscribe",
        "min_size",
        "match",
    ):
        if key in updates:
            data[key] = updates[key]
    # Explicit clear for older_than_days when null sent
    if "older_than_days" in updates and updates["older_than_days"] in (None, ""):
        data.pop("older_than_days", None)
    return add_stage_rule(path, data)


def delete_stage_rule(path: Path, rule_id: str) -> bool:
    ruleset = load_rules(path)
    before = len(ruleset.stage)
    ruleset.stage = [r for r in ruleset.stage if r.id != rule_id]
    if len(ruleset.stage) == before:
        return False
    save_rules(path, ruleset)
    return True


def _slug(text: str, prefix: str = "rule") -> str:
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in text.lower())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")[:48] or "item"
    return f"{prefix}-{cleaned}"


def _selection_to_rule_data(kind: str, value: Any, *, action: str) -> dict[str, Any]:
    prefix = "keep" if action == "keep" else {
        "from_address": "sender",
        "from_domain": "domain",
        "older_than_days": "older",
        "folder": "folder",
    }.get(kind, "rule")

    if kind == "from_address":
        addr = str(value).lower().strip()
        return {
            "id": _slug(addr, prefix if action == "keep" else "sender"),
            "label": ("Keep " if action == "keep" else "Sender ") + addr,
            "from_address": addr,
        }
    if kind == "from_domain":
        domain = str(value).lower().strip()
        return {
            "id": _slug(domain, prefix if action == "keep" else "domain"),
            "label": ("Keep domain " if action == "keep" else "Domain ") + domain,
            "from_domain": domain,
        }
    if kind == "from_domain_suffix":
        suf = _normalize_suffix_or_none(value)
        if not suf:
            raise ValueError("invalid domain suffix")
        slug = suf.lstrip(".")
        return {
            "id": f"keep-suffix-{slug}" if action == "keep" else f"suffix-{slug}",
            "label": (f"Keep *{suf} domains" if action == "keep" else f"Suffix {suf}"),
            "from_domain_suffix": suf,
        }
    if kind == "subject_contains":
        text = str(value).strip()
        if not text:
            raise ValueError("subject_contains value required")
        return {
            "id": _slug(text, "keep-subj" if action == "keep" else "subj"),
            "label": (f"Keep subject contains {text}" if action == "keep" else f"Subject {text}"),
            "subject_contains": text,
        }
    if kind == "folder":
        folder = str(value)
        return {
            "id": _slug(folder, prefix if action == "keep" else "folder"),
            "label": ("Keep folder " if action == "keep" else "Folder ") + folder,
            "folder": folder,
        }
    if kind == "older_than_days":
        if action == "keep":
            raise ValueError(
                "Age cutoffs can't be keep rules — keep is by sender, domain, or folder."
            )
        days = int(value)
        return {
            "id": f"older-than-{days}d",
            "label": f"Older than {days} days",
            "older_than_days": days,
        }
    if kind == "list_unsubscribe_older_than":
        if action == "keep":
            raise ValueError("List-Unsubscribe age rules are cleanup-only.")
        days = int(value)
        return {
            "id": f"list-unsub-older-{days}d",
            "label": f"List-Unsubscribe older than {days} days",
            "has_list_unsubscribe": True,
            "older_than_days": days,
        }
    raise ValueError(f"Unknown selection kind: {kind}")


def rules_from_insight_selections(
    path: Path,
    selections: list[dict[str, Any]],
    action: str = "stage",
    progress_cb: Any | None = None,
) -> list[Rule]:
    """
    Create/update stage or keep rules from Insights checkboxes.

    Loads rules.yaml once, applies all selections in memory, writes once.
    (Older code rewrote the YAML per selection — thousands of picks took minutes.)

    selection kinds:
      - from_address: value = email
      - from_domain: value = domain
      - older_than_days: value = int days (stage only)
      - list_unsubscribe_older_than: value = int days (stage only)
      - folder: value = folder name
    """
    action = (action or "stage").strip().lower()
    if action not in ("stage", "keep"):
        raise ValueError(f"Unknown action: {action}")

    # Materialize first so we can report total accurately
    pending: list[dict[str, Any]] = []
    for sel in selections:
        kind = str(sel.get("kind") or "").strip()
        value = sel.get("value")
        if value is None or value == "":
            continue
        pending.append(_selection_to_rule_data(kind, value, action=action))

    total = len(pending)
    if progress_cb:
        progress_cb(done=0, total=total, phase="start")

    ruleset = load_rules(path)
    created: list[Rule] = []
    for i, data in enumerate(pending):
        if action == "keep":
            rule = Rule.from_dict({**data, "action": "keep"}, "keep")
            ruleset.keep = [r for r in ruleset.keep if r.id != rule.id]
            ruleset.keep = [
                r for r in ruleset.keep if not _same_primary_criteria(r, rule)
            ]
            ruleset.keep.append(rule)
            ruleset.stage = [
                r for r in ruleset.stage if not _same_primary_criteria(r, rule)
            ]
        else:
            rule = Rule.from_dict(data, "stage")
            ruleset.stage = [r for r in ruleset.stage if r.id != rule.id]
            ruleset.stage.append(rule)
        created.append(rule)
        if progress_cb and ((i + 1) % 25 == 0 or i + 1 == total):
            progress_cb(done=i + 1, total=total, phase="apply")

    if progress_cb:
        progress_cb(done=total, total=total, phase="save")
    save_rules(path, ruleset)
    if progress_cb:
        progress_cb(done=total, total=total, phase="done")
    return created


def archive_dormant_stage_rules(
    profile: Any,
    *,
    sample_limit: int = 0,
) -> dict[str, Any]:
    """Mark active stage rules with zero current matches as active=false.

    Does not delete rules (they stay for future mail) but skips them in stage/preview
    so Guided and Suggestions stay fast. Pass profile with db_path + rules_path.
    """
    from mail_janitor.config import Profile
    from mail_janitor.db import init_db

    if not isinstance(profile, Profile):
        raise TypeError("profile must be a Profile")
    ruleset = load_rules(profile.rules_path)
    now_ts = int(time.time())
    keep_sql, keep_params = keep_exclusion_sql(ruleset, now_ts)
    conn = init_db(profile.db_path)
    archived: list[str] = []
    kept_active = 0
    try:
        for rule in ruleset.stage:
            if not rule.active:
                continue
            where, params = rule_sql_clauses(rule, now_ts)
            folder_sql, folder_params = profile.stage_folder_sql(rule)
            cnt = int(
                conn.execute(
                    f"SELECT COUNT(*) AS c FROM messages WHERE ({where}) AND ({keep_sql}){folder_sql}",
                    params + keep_params + folder_params,
                ).fetchone()["c"]
            )
            if cnt == 0:
                rule.active = False
                archived.append(rule.id)
            else:
                kept_active += 1
                if sample_limit and len(archived) + kept_active > sample_limit:
                    break
    finally:
        conn.close()
    if archived:
        save_rules(profile.rules_path, ruleset)
    return {
        "archived": len(archived),
        "still_active": kept_active,
        "archived_ids": archived[:50],
    }

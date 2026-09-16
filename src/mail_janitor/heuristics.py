"""Soft cleanup heuristics for Insights (never auto-move).

Also provides a metadata-only junk vs keep score for long-tail triage.
No body fetch, no LLM — From / subject / folder / List-Unsubscribe only.
"""

from __future__ import annotations

import re
from typing import Any


# Host fragments that often indicate marketing / automated mail.
_MARKETING_HOST_RE = re.compile(
    r"(^|\.)("
    r"mail|email|e|news|newsletter|promo|promotion|promotions|offers|offer|"
    r"marketing|mkt|info|notify|notification|notifications|updates|update|"
    r"deals|deal|bounce|em\.|reply|noreply|no-reply|donotreply"
    r")(\.|$)",
    re.I,
)

_PROMO_SUBJECT_RE = re.compile(
    r"("
    r"\b(unsubscribe|newsletter|limited time|act now|click here|buy now|"
    r"free shipping|%\s*off|\$\d+|win a |you've been selected|congrats|"
    r"congratulations|claim your|exclusive offer|special offer|"
    r"slash your|premiums?|geico|insurance quote|hot deal)"
    r"|\byeti\b|\bgutter offer\b"
    r")",
    re.I,
)

_CONVERSATION_SUB_RE = re.compile(r"^\s*(re|fw|fwd)\s*:", re.I)

_FREE_MAIL = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
}

_BULK_FOLDERS = {"bulk", "junk", "spam", "junk email", "bulk mail"}


def marketing_ish_domain(domain: str | None) -> bool:
    if not domain:
        return False
    d = domain.lower().strip()
    if d in _FREE_MAIL:
        return False
    return bool(_MARKETING_HOST_RE.search(d))


def _local_part(from_addr: str | None) -> str:
    addr = (from_addr or "").strip().lower()
    if "@" not in addr:
        return addr
    return addr.split("@", 1)[0]


def looks_random_local(local: str | None) -> bool:
    """Heuristic for machine-generated local-parts (a28fhkkv, hex tokens)."""
    if not local:
        return False
    local = local.split("+", 1)[0]
    if len(local) < 6:
        return False
    if re.fullmatch(r"[a-f0-9]{8,}", local, re.I):
        return True
    if re.search(r"(?:^|[^0-9])\d{5,}(?:$|[^0-9])", local) and not re.search(
        r"(?:19|20)\d{2}", local
    ):
        return True
    if len(local) >= 8 and re.fullmatch(r"[a-z0-9._-]+", local, re.I):
        letters = re.findall(r"[a-z]", local, re.I)
        vowels = len(re.findall(r"[aeiou]", local, re.I))
        if vowels / max(len(letters), 1) < 0.18:
            return True
    return False


def looks_human_local(local: str | None) -> bool:
    """first.last / first_last style locals — weak keep signal."""
    if not local:
        return False
    local = local.split("+", 1)[0]
    if re.search(
        r"(noreply|no-reply|donotreply|do-not-reply|mailer-daemon|postmaster)",
        local,
        re.I,
    ):
        return False
    return bool(re.fullmatch(r"[a-z]{2,}[._-][a-z]{2,}(?:[._-][a-z]{2,})?", local, re.I))


def score_message(msg: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only junk vs keep triage.

    Returns confidence in {junk, uncertain, keep}, numeric score (higher = junkier),
    and short flag labels for UI badges.
    """
    score = 0
    flags: list[str] = []

    lu = int(msg.get("list_unsubscribe") or 0) == 1
    if lu:
        score += 3
        flags.append("list-unsub")

    domain = (msg.get("from_domain") or "").lower().strip()
    if marketing_ish_domain(domain):
        score += 2
        flags.append("marketing-ish")

    subject = msg.get("subject") or ""
    if _CONVERSATION_SUB_RE.match(subject):
        score -= 3
        flags.append("conversation")
    if subject and _PROMO_SUBJECT_RE.search(subject):
        score += 2
        flags.append("promo-subject")

    local = _local_part(msg.get("from_addr"))
    if looks_random_local(local):
        score += 2
        flags.append("random-from")
    if looks_human_local(local):
        score -= 2
        flags.append("human-from")

    if domain in _FREE_MAIL and not lu:
        score -= 1
        flags.append("free-mail")

    folder = (msg.get("folder") or "").strip().lower()
    if folder in _BULK_FOLDERS:
        score += 2
        flags.append("bulk-folder")

    if score >= 3:
        confidence = "junk"
    elif score <= -2:
        confidence = "keep"
    else:
        confidence = "uncertain"

    return {
        "confidence": confidence,
        "score": score,
        "flags": flags,
    }


def annotate_sender(row: dict[str, Any], *, high_volume_min: int = 40) -> dict[str, Any]:
    """Add heuristic flags for a sender aggregate row."""
    cnt = int(row.get("cnt") or 0)
    unsub = int(row.get("list_unsub_cnt") or 0)
    pct = (unsub / cnt) if cnt else 0.0
    flags: list[str] = []
    if unsub > 0 and pct >= 0.25:
        flags.append("list-unsub")
    if cnt >= high_volume_min:
        flags.append("high-volume")
    if marketing_ish_domain(row.get("from_domain")):
        flags.append("marketing-ish")
    out = dict(row)
    out["list_unsub_pct"] = round(pct, 3)
    out["heuristic_flags"] = flags
    out["heuristic_likely"] = bool(flags)
    return out


def annotate_domain(row: dict[str, Any], *, high_volume_min: int = 80) -> dict[str, Any]:
    cnt = int(row.get("cnt") or 0)
    unsub = int(row.get("list_unsub_cnt") or 0)
    pct = (unsub / cnt) if cnt else 0.0
    flags: list[str] = []
    if unsub > 0 and pct >= 0.25:
        flags.append("list-unsub")
    if cnt >= high_volume_min:
        flags.append("high-volume")
    if marketing_ish_domain(row.get("from_domain")):
        flags.append("marketing-ish")
    out = dict(row)
    out["list_unsub_pct"] = round(pct, 3)
    out["heuristic_flags"] = flags
    out["heuristic_likely"] = bool(flags)
    return out

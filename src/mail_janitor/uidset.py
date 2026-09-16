"""IMAP UID set helpers (RFC 3501 / COPYUID)."""

from __future__ import annotations

import re


_TOKEN_RE = re.compile(r"(\d+)(?::(\d+))?")


def expand_uid_set(spec: str | bytes) -> list[int]:
    """Expand an IMAP UID set like '1,3:5,10' into a sorted unique list."""
    if isinstance(spec, (bytes, bytearray)):
        spec = bytes(spec).decode("ascii", errors="replace")
    spec = spec.strip()
    if not spec:
        return []
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        m = _TOKEN_RE.fullmatch(part)
        if not m:
            raise ValueError(f"Invalid UID set token: {part!r}")
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) is not None else start
        if end < start:
            start, end = end, start
        out.extend(range(start, end + 1))
    return out


def compact_uid_set(uids: list[int]) -> str:
    """Compact sorted UIDs into an IMAP set string (ranges where contiguous)."""
    if not uids:
        return ""
    ordered = sorted(set(int(u) for u in uids))
    parts: list[str] = []
    start = prev = ordered[0]
    for uid in ordered[1:]:
        if uid == prev + 1:
            prev = uid
            continue
        parts.append(str(start) if start == prev else f"{start}:{prev}")
        start = prev = uid
    parts.append(str(start) if start == prev else f"{start}:{prev}")
    return ",".join(parts)


def map_copyuid_sets(source_set: str | bytes, dest_set: str | bytes) -> dict[int, int]:
    """Pair COPYUID source/dest sets 1:1 in expansion order."""
    sources = expand_uid_set(source_set)
    dests = expand_uid_set(dest_set)
    if len(sources) != len(dests):
        # Best-effort: zip what we can; missing dests omitted
        n = min(len(sources), len(dests))
        return {sources[i]: dests[i] for i in range(n)}
    return dict(zip(sources, dests))

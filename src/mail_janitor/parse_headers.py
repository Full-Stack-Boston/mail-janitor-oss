"""Header parsing helpers (no body)."""

from __future__ import annotations

import email.header
import email.utils
import re
from datetime import datetime, timezone
from email.parser import HeaderParser
from typing import Any


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        parts = email.header.decode_header(value)
    except Exception:
        return str(value).strip()
    out: list[str] = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            enc = charset or "utf-8"
            try:
                out.append(chunk.decode(enc, errors="replace"))
            except (LookupError, UnicodeError, ValueError):
                # Malformed RFC2047 charsets (e.g. "base64", garbage-…-8) show up in spam.
                out.append(chunk.decode("utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out).strip()


def extract_address(raw: str | None) -> str:
    if not raw:
        return ""
    decoded = decode_header_value(raw)
    name, addr = email.utils.parseaddr(decoded)
    if addr:
        return addr.lower()
    m = EMAIL_RE.search(decoded)
    return m.group(0).lower() if m else decoded.lower()


def extract_domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower()


def parse_date_ts(raw: str | None) -> tuple[int | None, str]:
    if not raw:
        return None, ""
    decoded = decode_header_value(raw)
    try:
        dt = email.utils.parsedate_to_datetime(decoded)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp()), decoded
    except (TypeError, ValueError, IndexError, OverflowError):
        return None, decoded


def parse_header_bytes(data: bytes | str) -> dict[str, Any]:
    empty = {
        "from_addr": "",
        "from_domain": "",
        "subject": "",
        "date_ts": None,
        "date_raw": "",
        "message_id": "",
        "list_unsubscribe": 0,
    }
    try:
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = data
        msg = HeaderParser().parsestr(text)
        from_addr = extract_address(msg.get("From"))
        subject = decode_header_value(msg.get("Subject"))
        date_ts, date_raw = parse_date_ts(msg.get("Date"))
        message_id = (msg.get("Message-ID") or "").strip()
        # Prefer header presence over truthy value: some senders emit an empty
        # List-Unsubscribe line, and List-Unsubscribe-Post alone still marks bulk mail.
        header_names = {k.lower() for k in msg.keys()}
        list_unsub = (
            1
            if (
                "list-unsubscribe" in header_names
                or "list-unsubscribe-post" in header_names
            )
            else 0
        )
        return {
            "from_addr": from_addr,
            "from_domain": extract_domain(from_addr),
            "subject": subject,
            "date_ts": date_ts,
            "date_raw": date_raw,
            "message_id": message_id,
            "list_unsubscribe": list_unsub,
        }
    except Exception:
        # Never let a single malformed header nuke an entire scan batch.
        return empty


def format_size(n: int | None) -> str:
    if n is None:
        return "0 B"
    n = int(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def format_ts(ts: int | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

"""IMAP client wrapper — headers-only scan, on-request body, MOVE only."""

from __future__ import annotations

import imaplib
import re
import time
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message
from typing import Any, Callable, Iterator

from mail_janitor.parse_headers import parse_header_bytes
from mail_janitor.uidset import compact_uid_set, map_copyuid_sets


LIST_RE = re.compile(
    r'\((?P<flags>.*?)\)\s+(?P<delim>"[^"]*"|NIL)\s+(?P<name>"[^"]*"|[^"\s]+)'
)
UID_RE = re.compile(rb"UID\s+(\d+)", re.I)
SIZE_RE = re.compile(rb"RFC822\.SIZE\s+(\d+)", re.I)
FLAGS_RE = re.compile(rb"FLAGS\s+\(([^)]*)\)", re.I)


@dataclass
class FolderInfo:
    name: str
    flags: str


class ImapClient:
    def __init__(
        self,
        host: str,
        port: int,
        email: str,
        password: str,
        ssl: bool = True,
        timeout: float = 120.0,
    ):
        self.host = host
        self.port = port
        self.email = email
        self.password = password
        self.ssl = ssl
        self.timeout = timeout
        self._imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

    def connect(self) -> None:
        if self.ssl:
            self._imap = imaplib.IMAP4_SSL(self.host, self.port, timeout=self.timeout)
        else:
            self._imap = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
        typ, _ = self._imap.login(self.email, self.password)
        if typ != "OK":
            raise RuntimeError(f"IMAP login failed: {typ}")

    def close(self) -> None:
        if not self._imap:
            return
        try:
            self._imap.close()
        except Exception:
            pass
        try:
            self._imap.logout()
        except Exception:
            pass
        self._imap = None

    def __enter__(self) -> "ImapClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def imap(self) -> imaplib.IMAP4:
        if not self._imap:
            raise RuntimeError("Not connected")
        return self._imap

    def list_folders(self) -> list[FolderInfo]:
        typ, data = self.imap.list()
        if typ != "OK" or not data:
            return []
        folders: list[FolderInfo] = []
        for item in data:
            if not item:
                continue
            line = item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
            m = LIST_RE.search(line)
            if not m:
                continue
            name = m.group("name").strip('"')
            folders.append(FolderInfo(name=name, flags=m.group("flags")))
        return folders

    def select(self, folder: str, readonly: bool = True) -> tuple[int, int | None]:
        """Select folder. Returns (exists_count, uidvalidity)."""
        typ, data = self.imap.select(self._quote(folder), readonly=readonly)
        if typ != "OK":
            raise RuntimeError(f"Cannot select folder {folder!r}: {typ} {data}")
        exists = int(data[0]) if data and data[0] else 0
        uidvalidity = None
        typ2, data2 = self.imap.response("UIDVALIDITY")
        if typ2 == "OK" and data2 and data2[0]:
            try:
                uidvalidity = int(data2[0])
            except (TypeError, ValueError):
                pass
        # Some servers only expose UIDVALIDITY via STATUS
        if uidvalidity is None:
            try:
                typ3, data3 = self.imap.status(self._quote(folder), "(UIDVALIDITY)")
                if typ3 == "OK" and data3 and data3[0]:
                    m = re.search(rb"UIDVALIDITY\s+(\d+)", data3[0])
                    if m:
                        uidvalidity = int(m.group(1))
            except Exception:
                pass
        return exists, uidvalidity

    def uid_search_all_above(self, last_uid: int) -> list[int]:
        if last_uid > 0:
            criteria = f"UID {last_uid + 1}:*"
        else:
            criteria = "ALL"
        typ, data = self.imap.uid("search", None, criteria)
        if typ != "OK" or not data or not data[0]:
            return []
        uids = [int(x) for x in data[0].split() if x.isdigit() or x.decode().isdigit()]
        # Filter out the last_uid itself if server returned it
        return [u for u in uids if u > last_uid]

    def fetch_headers(self, uids: list[int]) -> list[dict[str, Any]]:
        if not uids:
            return []
        uid_set = ",".join(str(u) for u in uids)
        # Full HEADER (not HEADER.FIELDS): Yahoo IMAP silently omits List-Unsubscribe
        # from HEADER.FIELDS even when the message has it.
        #
        # IMPORTANT: do NOT fetch BODYSTRUCTURE in the same UID FETCH as HEADER.
        # Yahoo embeds nested {N}-literals inside BODYSTRUCTURE (filenames, etc.);
        # imaplib then mis-associates those literals as HEADER payloads (or drops
        # HEADER entirely), leaving from/subject blank while SIZE still parses.
        fetch_spec = "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])"
        typ, data = self.imap.uid("fetch", uid_set, fetch_spec)
        if typ != "OK" or not data:
            return []
        rows = self._parse_fetch_headers(data)
        # Attachment heuristic via a separate BODYSTRUCTURE fetch (no body bytes).
        try:
            typ2, data2 = self.imap.uid("fetch", uid_set, "(UID BODYSTRUCTURE)")
            if typ2 == "OK" and data2:
                attach_by_uid: dict[int, int | None] = {}
                for item in data2:
                    meta = b""
                    if isinstance(item, tuple) and item:
                        if isinstance(item[0], (bytes, bytearray)):
                            meta = bytes(item[0])
                    elif isinstance(item, (bytes, bytearray)):
                        meta = bytes(item)
                    uid_m = UID_RE.search(meta)
                    if not uid_m:
                        continue
                    attach_by_uid[int(uid_m.group(1))] = self._attachment_from_meta(meta)
                for row in rows:
                    if row["uid"] in attach_by_uid:
                        row["has_attachment"] = attach_by_uid[row["uid"]]
        except Exception:
            pass
        return rows

    def fetch_body(self, uid: int) -> tuple[str, str]:
        """On-request full message. Returns (content_type_hint, text). Not persisted."""
        typ, data = self.imap.uid("fetch", str(uid), "(BODY.PEEK[])")
        if typ != "OK" or not data:
            raise RuntimeError(f"Failed to fetch UID {uid}")
        raw = self._extract_body_bytes(data)
        if raw is None:
            raise RuntimeError(f"Empty body for UID {uid}")
        msg = message_from_bytes(raw)
        text = self._message_to_text(msg)
        return ("text/plain", text)

    def ensure_folder(self, folder: str) -> None:
        typ, _ = self.imap.create(self._quote(folder))
        # OK or ALREADYEXISTS both fine
        if typ not in ("OK", "NO"):
            pass

    def move_uid(self, uid: int, dest_folder: str) -> int | None:
        """Move one UID to dest. Returns dest UID if known."""
        mapping = self.move_uids([uid], dest_folder)
        return mapping.get(uid)

    def move_uids(self, uids: list[int], dest_folder: str) -> dict[int, int | None]:
        """Move many UIDs in one IMAP round-trip. Returns source_uid → dest_uid."""
        if not uids:
            return {}
        uid_set = compact_uid_set(uids)
        dest = self._quote(dest_folder)
        # Prefer MOVE (RFC 6851); fall back to COPY + \\Deleted (no EXPUNGE in v1).
        try:
            typ, data = self.imap.uid("move", uid_set, dest)
            if typ == "OK":
                return self._parse_copyuid_map(data, uids)
        except Exception:
            pass
        typ, data = self.imap.uid("copy", uid_set, dest)
        if typ != "OK":
            detail = data[0] if data else b""
            if isinstance(detail, (bytes, bytearray)):
                detail = detail.decode("utf-8", "replace")
            raise RuntimeError(
                f"COPY failed for UIDs {uid_set} → {dest_folder}: {typ}"
                + (f" {detail}" if detail else "")
            )
        mapping = self._parse_copyuid_map(data, uids)
        self.imap.uid("store", uid_set, "+FLAGS", "(\\Deleted)")
        # Do not EXPUNGE — safety invariant for v1
        return mapping

    def _parse_copyuid_map(
        self, data: Any, requested: list[int]
    ) -> dict[int, int | None]:
        """Parse COPYUID into source→dest map; fill missing requested UIDs with None."""
        result: dict[int, int | None] = {int(u): None for u in requested}
        if not data:
            return result
        parts: list[bytes] = []
        for x in data:
            if isinstance(x, (bytes, bytearray)):
                parts.append(bytes(x))
            elif isinstance(x, tuple):
                for y in x:
                    if isinstance(y, (bytes, bytearray)):
                        parts.append(bytes(y))
        blob = b" ".join(parts)
        # COPYUID uidvalidity source_set dest_set
        m = re.search(
            rb"COPYUID\s+\d+\s+([0-9,:]+)\s+([0-9,:]+)",
            blob,
            re.I,
        )
        if not m:
            # Single-dest legacy shape
            m1 = re.search(rb"COPYUID\s+\d+\s+\S+\s+(\d+)", blob, re.I)
            if m1 and len(requested) == 1:
                result[int(requested[0])] = int(m1.group(1))
            return result
        paired = map_copyuid_sets(m.group(1), m.group(2))
        for src, dest in paired.items():
            if src in result:
                result[src] = dest
            else:
                # Server may echo a different ordering; still record known pairs
                result[src] = dest
        return result

    def _quote(self, folder: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9._/-]+", folder):
            return folder
        escaped = folder.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _parse_fetch_headers(self, data: list[Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        i = 0
        while i < len(data):
            item = data[i]
            if item is None or item == b")":
                i += 1
                continue
            if isinstance(item, tuple) and len(item) >= 2:
                meta = item[0] if isinstance(item[0], (bytes, bytearray)) else b""
                payload = item[1] if isinstance(item[1], (bytes, bytearray)) else b""
                parsed = self._row_from_fetch(meta, payload)
                if parsed:
                    results.append(parsed)
                i += 1
                continue
            if isinstance(item, (bytes, bytearray)):
                # Sometimes meta is alone then body follows
                meta = bytes(item)
                payload = b""
                if i + 1 < len(data) and isinstance(data[i + 1], (bytes, bytearray)):
                    # Could be body; check if looks like headers
                    nxt = bytes(data[i + 1])
                    if b":" in nxt[:200] or nxt.startswith(b"From") or nxt.startswith(b"Date"):
                        payload = nxt
                        i += 1
                parsed = self._row_from_fetch(meta, payload)
                if parsed:
                    results.append(parsed)
            i += 1
        return results

    def _row_from_fetch(self, meta: bytes, payload: bytes) -> dict[str, Any] | None:
        uid_m = UID_RE.search(meta)
        if not uid_m:
            return None
        uid = int(uid_m.group(1))
        size_m = SIZE_RE.search(meta)
        size = int(size_m.group(1)) if size_m else 0
        flags_m = FLAGS_RE.search(meta)
        flags = flags_m.group(1).decode("utf-8", errors="replace") if flags_m else ""
        has_attachment = self._attachment_from_meta(meta)
        try:
            headers = parse_header_bytes(payload) if payload else {
                "from_addr": "",
                "from_domain": "",
                "subject": "",
                "date_ts": None,
                "date_raw": "",
                "message_id": "",
                "list_unsubscribe": 0,
            }
        except Exception:
            headers = {
                "from_addr": "",
                "from_domain": "",
                "subject": "",
                "date_ts": None,
                "date_raw": "",
                "message_id": "",
                "list_unsubscribe": 0,
            }
        return {
            "uid": uid,
            "size": size,
            "flags": flags,
            "has_attachment": has_attachment,
            **headers,
        }

    @staticmethod
    def _attachment_from_meta(meta: bytes) -> int | None:
        """Infer attachment from BODYSTRUCTURE text in FETCH meta (not body content)."""
        low = meta.lower()
        if b"bodystructure" not in low and b"attachment" not in low:
            # Structure may be in a separate FETCH item; unknown if absent
            if b"(" not in meta:
                return None
        if b"attachment" in low or b'"filename"' in low or b"filename=" in low:
            return 1
        # Multipart/mixed often means attachments, but not always — stay conservative
        if b'"mixed"' in low and b"boundary" in low:
            return 1
        if b"bodystructure" in low:
            return 0
        return None

    def _extract_body_bytes(self, data: list[Any]) -> bytes | None:
        for item in data:
            if isinstance(item, tuple) and len(item) >= 2:
                if isinstance(item[1], (bytes, bytearray)):
                    return bytes(item[1])
            if isinstance(item, (bytes, bytearray)) and len(item) > 100:
                # skip IMAP literals that are just meta
                if item.startswith(b"(") and b"BODY" in item[:80]:
                    continue
                return bytes(item)
        return None

    def _message_to_text(self, msg: Message) -> str:
        lines = [
            f"From: {msg.get('From', '')}",
            f"To: {msg.get('To', '')}",
            f"Cc: {msg.get('Cc', '')}",
            f"Date: {msg.get('Date', '')}",
            f"Subject: {msg.get('Subject', '')}",
            "",
        ]
        body = self._extract_text_part(msg)
        lines.append(body or "[No plain/html text part found]")
        return "\n".join(lines)

    def _extract_text_part(self, msg: Message) -> str:
        if msg.is_multipart():
            plain = None
            html = None
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition") or "")
                if "attachment" in disp.lower():
                    continue
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    continue
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if ctype == "text/plain" and plain is None:
                    plain = text
                elif ctype == "text/html" and html is None:
                    html = text
            if plain:
                return plain
            if html:
                return re.sub(r"<[^>]+>", " ", html)
            return ""
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            return str(msg.get_payload() or "")
        if payload is None:
            return str(msg.get_payload() or "")
        charset = msg.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")


def with_backoff(fn: Callable[[], Any], retries: int = 5, base: float = 1.5) -> Any:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            return fn()
        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError, TimeoutError) as e:
            last = e
            time.sleep(base ** attempt)
    assert last is not None
    raise last


def chunked(items: list[int], size: int) -> Iterator[list[int]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]

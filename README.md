# Mail Janitor

Safe bulk cleanup for large mailboxes. Headers-only local index, interactive rules, and an explicit confirm phrase before anything moves.

**Try it / fork it**

| | |
|--|--|
| Museum demo (Authentik-gated) | [mail-janitor.fullstackboston.com](https://mail-janitor.fullstackboston.com/guide) |
| Open source | [github.com/Full-Stack-Boston/mail-janitor-oss](https://github.com/Full-Stack-Boston/mail-janitor-oss) |

Yahoo IMAP is the first-class pack; Zoho, Gmail IMAP, and generic IMAP are also available. Native Gmail API / Microsoft Graph are deferred until IMAP coverage is proven.

## What it does

Hundreds of thousands of messages are painful in a webmail UI. Mail Janitor:

1. **Scans headers only** over IMAP into a per-profile SQLite index (`mail.db`) — resume-friendly, overnight-OK.
2. **Discovers** senders, domains, list-unsubscribe patterns, and size/age shapes so you can invent rules.
3. **Stages** candidates locally (mailbox untouched) from YAML keep/stage rules.
4. **Reviews** in a guided UI (`/guide`) or advanced desk — deselect false positives, keep a sender, open a body only on request.
5. **Applies** moves to a holding folder (`ready2delete` by default), with optional undo, then optional Trash (Yahoo auto-empties Trash after 7 days).

Every move is appended to `profiles/<name>/audit.jsonl`. There is **no IMAP EXPUNGE** in v1 — moves only.

## Safety model (read this)

1. **Scan never downloads bodies.** The index stores headers/size only.
2. **Review list is metadata only.** Opening a message fetches the body **on request** (brief memory cache; not written to `mail.db`).
3. **Default apply target is `ready2delete`**, not Trash. Undo returns mail to the original folder.
4. **Trash is a separate step.** Yahoo **automatically empties Trash after 7 days** and you **cannot** change that ([Yahoo Help](https://help.yahoo.com/kb/trash-spam-folders-regularly-emptied-sln3518.html)). Use `to-trash` only when you accept that clock.
5. **End of a round:** restore Intentionally Kept → Inbox (`RESTORE KEPT TO INBOX`), then drain `ready2delete` → Trash (`MOVE TO TRASH`, optionally `--all`).
6. Confirm phrases (exact): `MOVE TO READY2DELETE` · `UNDO FROM READY2DELETE` · `MOVE TO INTENTIONALLY KEPT` · `RESTORE KEPT TO INBOX` · `MOVE TO TRASH`

## Quick start (local)

```bash
git clone https://github.com/Full-Stack-Boston/mail-janitor-oss.git
cd mail-janitor-oss
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

mail-janitor init-profile myyahoo
# edit profiles/myyahoo/config.toml
# edit profiles/myyahoo/.env  → MAIL_JANITOR_EMAIL + MAIL_JANITOR_APP_PASSWORD
# (or use Get started → Connect in the UI)

mail-janitor scan -p myyahoo
mail-janitor discover -p myyahoo
$EDITOR profiles/myyahoo/rules.yaml
mail-janitor preview -p myyahoo
mail-janitor stage -p myyahoo --clear
mail-janitor review -p myyahoo
# open http://127.0.0.1:8787/guide
```

Apply only after review:

```bash
mail-janitor preflight -p myyahoo
mail-janitor apply -p myyahoo --confirm "MOVE TO READY2DELETE"
# optional
mail-janitor undo -p myyahoo --confirm "UNDO FROM READY2DELETE"
```

Finish a round (protected mail back to Inbox; junk holding folder → Trash):

```bash
mail-janitor end-stage -p myyahoo
mail-janitor restore-kept -p myyahoo --confirm "RESTORE KEPT TO INBOX"
mail-janitor to-trash -p myyahoo --confirm "MOVE TO TRASH" --all
```

The guided UI step **5 · Done** and Advanced → Finish a round expose the same actions.

### Yahoo setup

1. Enable **IMAP** in Yahoo Mail settings.
2. Enable **two-step verification**.
3. Create an **app password** (Account Security → app passwords).  
   Some accounts block app-password creation; fix that before scanning.
4. Never commit the app password.

IMAP defaults: `imap.mail.yahoo.com:993` (SSL).

### Docker / dual ports

See [`docker-compose.yml`](docker-compose.yml) and [`docs/DEPLOY.md`](docs/DEPLOY.md).

| Instance | Default port | Data | Purpose |
|----------|--------------|------|---------|
| Personal | `8787` | `profiles/` | Your live mailbox |
| Demo / client | `8788` | ephemeral sessions | Authentik-gated museum / client product |

Compose env knobs live in [`.env.example`](.env.example) (`MAIL_JANITOR_PROFILE`, ports, profile roots, optional Nathan ntfy).

## Configuration

### Profile layout

Each profile under `profiles/<name>/` is isolated:

| File | Role |
|------|------|
| `config.toml` | Provider pack, IMAP host/port, folder names |
| `.env` | `MAIL_JANITOR_EMAIL`, `MAIL_JANITOR_APP_PASSWORD` (gitignored) |
| `mail.db` | Headers-only SQLite index (gitignored) |
| `rules.yaml` | Keep + stage rules |
| `audit.jsonl` | Append-only move log |
| `firewall.yaml` | Optional sender/domain firewall |

Ship only `profiles/_example/` in public trees — see [`docs/SANITIZE.md`](docs/SANITIZE.md).

### Example `rules.yaml`

```yaml
keep:
  - id: keep-bank
    from_domain: mybank.com

stage:
  - id: old-newsletters
    label: Newsletters older than 2 years
    has_list_unsubscribe: true
    older_than_days: 730
```

Keep-rules **always win** (excluded from staging/preview).

Rule fields: `from_domain`, `from_address`, `subject_contains`, `older_than_days`, `folder`, `has_list_unsubscribe`, `min_size`, `match` (`all`/`any`).

### Guided UI

```bash
mail-janitor review -p myyahoo
# http://127.0.0.1:8787/guide
```

**Get started** walks Connect → Scan → Protect → Clean → Done.  
**Advanced** keeps Insights, Keep explorer, Suggested rules, and Rules.

Preview samples are **from the SQLite header index** (from, subject, date, folder, size, uid) — not body peeks. Yahoo IMAP does not provide a Zoho-style snippet in headers.

## How it was built (fork notes)

Stack is intentionally small and local-first:

| Layer | Choice |
|-------|--------|
| CLI | Click (`mail-janitor` entry point) |
| Index | SQLite via stdlib (`db.py`) — headers/size/UID only |
| IMAP | Python `imaplib` + provider packs under `providers/` (Yahoo, Zoho, Gmail IMAP, generic) |
| Rules | YAML → matcher in `rules.py` / staging in `stage.py` |
| Moves | `apply.py` with confirm phrases + `audit.py` JSONL |
| UI | FastAPI + Jinja2 templates + static CSS/JS under `web/` |
| Client product | `client_sessions.py` — ephemeral workspaces, TTL wipe, Authentik identity headers |

Useful seams if you fork:

- **New provider:** add a pack in `src/mail_janitor/providers/` and register it in `packs.py`.
- **New rule field:** extend the YAML schema + matcher in `rules.py`, cover with pytest (package is gated at **100%** coverage).
- **UI flow:** templates in `src/mail_janitor/web/templates/`; guide vs advanced share the same API.
- **Deploy:** personal `:8787` vs client `:8788` — see `docs/DEPLOY.md` and `scripts/run-dual.sh`.

Tests:

```bash
pytest
```

## Lab / Mission Control (operators)
Status endpoint for cards: `GET /api/mission-control/status`.  
Portal card (after site deploy): `/portal/mail-janitor`.

Personalized profiles stay on a private volume; public/OSS trees only ship `profiles/_example/`.

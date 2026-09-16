# Mail Janitor

Open-source safe bulk mail cleanup (IMAP). Self-host with Docker Compose or a local venv.

Safe bulk cleanup for large mailboxes (Yahoo IMAP first; Gmail/others later).  
Headers-only local index, interactive rules, review before anything moves.

## Why not Yahoo’s web UI?

Hundreds of thousands of messages are painful there. Mail Janitor scans metadata over IMAP into SQLite, helps you invent rules from discovery stats, stages candidates, and only moves mail after you review and type a confirm phrase.

## Safety model (read this)

1. **Scan never downloads bodies.** The index stores headers/size only.
2. **Review list is metadata only.** Opening a message fetches the body **on request** (memory cache briefly; not written to `mail.db`).
3. **Default apply target is `ready2delete`**, not Trash. You can undo from there back to the original folder.
4. **Trash is a separate step.** Yahoo **automatically empties Trash after 7 days** and you **cannot** change that ([Yahoo Help](https://help.yahoo.com/kb/trash-spam-folders-regularly-emptied-sln3518.html)). Use `to-trash` only when you accept that clock.
5. **No IMAP EXPUNGE in v1.** Moves only.
6. Every move is appended to `profiles/<name>/audit.jsonl`.

Confirm phrases (exact):

- `MOVE TO READY2DELETE`
- `UNDO FROM READY2DELETE`
- `MOVE TO TRASH`

## Yahoo setup

1. Enable **IMAP** in Yahoo Mail settings.
2. Enable **two-step verification**.
3. Create an **app password** (Account Security → app passwords).  
   Some accounts block app-password creation; fix that before scanning.
4. Never commit the app password.

IMAP defaults: `imap.mail.yahoo.com:993` (SSL).

## Install

```bash
cd .
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Profile (multi-account)

```bash
mail-janitor init-profile myyahoo
# edit profiles/myyahoo/config.toml
# edit profiles/myyahoo/.env  → MAIL_JANITOR_EMAIL + MAIL_JANITOR_APP_PASSWORD
# (or use Get started → Connect in the UI)
```

Each profile has isolated `mail.db`, `rules.yaml`, and `audit.jsonl`.

## Workflow

```bash
# 1) Headers-only scan (resume-friendly; overnight OK)
mail-janitor scan -p myyahoo

# 2) See what you have
mail-janitor discover -p myyahoo

# 3) Edit rules as you go
$EDITOR profiles/myyahoo/rules.yaml
mail-janitor preview -p myyahoo

# 4) Stage candidates (local DB only — mailbox untouched)
mail-janitor stage -p myyahoo --clear

# 5) Review in the local UI
mail-janitor review -p myyahoo
# open http://127.0.0.1:8787/review
# deselect false positives, Keep sender, Open body only when needed

# 6) Apply (CLI or UI) — moves to ready2delete
mail-janitor preflight -p myyahoo
mail-janitor apply -p myyahoo --confirm "MOVE TO READY2DELETE"

# 7) Optional undo while still in ready2delete
mail-janitor undo -p myyahoo --confirm "UNDO FROM READY2DELETE"

# 8) Optional: start the 7-day Trash clock in batches
mail-janitor to-trash -p myyahoo --confirm "MOVE TO TRASH" --batch-size 100
```

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

## Preview samples

Sample rows are **from the SQLite header index** (from, subject, date, folder, size, uid).  
They are **not** body peeks trimmed for display. Yahoo IMAP does not provide a Zoho-style snippet in headers.

## Future providers

IMAP packs: **Yahoo**, **Zoho**, **Gmail (IMAP)**, and **generic IMAP**.  
Native Gmail API / Microsoft Graph are deferred until IMAP coverage is proven.

## Guided UI (elderly-friendly)

```bash
mail-janitor review -p myyahoo
# open http://127.0.0.1:8787/guide
```

**Get started** walks Connect → Scan → Protect → Clean → Done.  
**Advanced** keeps Insights, Keep explorer, Suggested rules, and Rules.

## Dual deploy (personal + generic review)

See [`docs/DEPLOY.md`](docs/DEPLOY.md).

- **Personal:** `http://127.0.0.1:8787/guide` (live profile under `profiles/`)
- **Demo / review:** `http://127.0.0.1:8788/guide` (isolated `deploy/demo-profiles/`, example identity only)

Mission Control card (after site deploy): `/portal/mail-janitor`

## Mission Control deploy

See `docker-compose.yml` and [`docs/SANITIZE.md`](docs/SANITIZE.md).  
Personalized profiles stay on a private volume; the git tree only ships `profiles/_example/`.

Status endpoint for cards: `GET /api/mission-control/status`.

## Tests

```bash
pytest
```

## Vaultwarden (lab)

Store the Yahoo IMAP app password as Login handle **`lab/mail-janitor-yahoo-imap`** (FSB/Machine) via Nathan `secrets.store` — do not paste it in chat.

```bash
# On fsb-03 (Nathan + bw unlock). Unlock file must exist:
#   /opt/stacks/nathan/secrets/vw-master  (mode 600)
. /opt/fsb/config/agent/cli.env
export NATHAN_URL=http://127.0.0.1:9102

# Option A — interactive prompt
/opt/fsb/data/repos/mail-janitor/scripts/store-yahoo-imap-in-vault.sh --username 'you@yahoo.com'

# Option B — staged file
printf '%s' 'YAHOO_APP_PASSWORD' > /tmp/yahoo-imap-app-pw && chmod 600 /tmp/yahoo-imap-app-pw
/opt/fsb/data/repos/mail-janitor/scripts/store-yahoo-imap-in-vault.sh \
  --username 'you@yahoo.com' --password-file /tmp/yahoo-imap-app-pw
shred -u /tmp/yahoo-imap-app-pw
```

Then put the same values in `profiles/<name>/.env` as `MAIL_JANITOR_EMAIL` + `MAIL_JANITOR_APP_PASSWORD` (local SoT for the tool).

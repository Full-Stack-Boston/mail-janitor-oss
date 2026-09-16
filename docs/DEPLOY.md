# Dual deploy (personal + Authentik client)

## What runs where

| Instance | Port | Data root | Purpose |
|----------|------|-----------|---------|
| Personal | **8787** | `profiles/` (live yahoo, gitignored) | Your mailbox cleanup (FSB theme) |
| Client | **8788** | `deploy/client-sessions/` (ephemeral, gitignored) | Authentik-gated client product |

Status API (both): `GET /api/mission-control/status`  
Guided UI (direct): `/guide`

## Public URLs

| Instance | URL | Access |
|----------|-----|--------|
| Personal | https://fullstackboston.com/portal/mail-janitor/app/guide | Authentik (Mission Control) |
| Client | https://mail-janitor.fullstackboston.com/guide | Authentik app **Mail Janitor** — group `mail-janitor-clients` only |
| Portal card | https://fullstackboston.com/portal/mail-janitor | Authentik |
| Legacy demo path | https://fullstackboston.com/portal/mail-janitor/demo/… | **302** → client subdomain |

Client NPM host **49**: `mail-janitor.fullstackboston.com` → `100.64.0.5:8788` (wildcard cert **22**) with Authentik forward-auth `advanced_config` (identity headers + mesh fail-fast). Because this app is **`forward_single`** (not Domain SSO), login start/callback must stay on the app host (`/outpost.goauthentik.io/…` → `authentik-proxy`); do **not** redirect start to `auth.fullstackboston.com` or you get `ERR_TOO_MANY_REDIRECTS`. Identity headers must be set inside a custom `location /` in advanced_config — NPM’s auto `location /` sets `proxy_set_header Upgrade/Connection`, which makes nginx drop server-level `X-authentik-*` headers (app then 401s with “missing X-authentik-uid” after a successful login). Provision / refresh:

```bash
fsb lab npm upsert \
  --domain mail-janitor.fullstackboston.com \
  --forward-host 100.64.0.5 \
  --forward-port 8788 \
  --certificate-id 22 \
  --advanced-config-file deploy/npm-mail-janitor-authentik.conf \
  --confirm
```

(Or Nathan `POST /v1/tools/npm.hosts.upsert` with the same fields + `advanced_config`.)

## Client mode (ephemeral)

Env on the `:8788` process (`scripts/run-dual.sh`):

| Variable | Value |
|----------|--------|
| `MAIL_JANITOR_CLIENT_MODE` | `1` |
| `MAIL_JANITOR_SESSION_TTL_HOURS` | `12` |
| `MAIL_JANITOR_SESSIONS_DIR` | `deploy/client-sessions/` |
| `MAIL_JANITOR_THEME` | `demo` (daylight skin) |
| `MAIL_JANITOR_PUBLIC_BASE` | empty (app at domain root) |

**Identity:** NPM/Authentik must send `X-authentik-uid` + `X-authentik-email`. Missing headers → `401` (defense in depth). Workspace key = uid under `SESSIONS_DIR/<uid>/`.

**Retention:**

- Session-only DB / audit for the active workspace
- Credentials stay in memory (optional 0600 session secrets file under the workspace) — **never** durable profile `.env`
- **End session** (`POST /api/session/end`) wipes the workspace immediately
- Idle reaper deletes workspaces with no activity for `SESSION_TTL_HOURS` (default 12)
- UI banner + “End session & erase my data”

**Hardening:** IMAP host allowlist for known providers; private/link-local `imap_host` rejected in client mode.

### Invite runbook (Authentik)

1. Create (or invite) the user in Authentik
2. Add them to group **`mail-janitor-clients`** (Domain SSO / Mission Control alone does **not** grant Mail Janitor)
3. Share https://mail-janitor.fullstackboston.com/guide
4. Operators testing: add themselves to `mail-janitor-clients`

Authentik objects (do **not** fold into Domain SSO application):

| Object | Name / value |
|--------|----------------|
| Group | `mail-janitor-clients` |
| Proxy Provider | **Mail Janitor Clients** — `forward_single`, external host `https://mail-janitor.fullstackboston.com` |
| Redirect URIs | Must include `https://mail-janitor.fullstackboston.com/outpost.goauthentik.io/callback?X-authentik-auth-callback=true` (empty URIs → Authentik “Redirect URI Error”) |
| OAuth mappings | Must include default Proxy outpost + OpenID `openid`/`email`/`profile` (+ entitlements). Empty mappings → authorize `invalid_request` / redirect loop |
| Grant types | Must include `authorization_code` (empty `grant_types` → immediate `invalid_request` / “otherwise malformed”) |
| Flows | Authorization: implicit consent; Invalidation: `default-provider-invalidation-flow`; Authentication flow: leave empty (like Domain SSO) |
| Application | **Mail Janitor** (`slug=mail-janitor`) — policy: members of `mail-janitor-clients` only |
| Outpost | Attach provider to **`fsb-03 NPM forward-auth`** (alongside Domain SSO) |

### Verify checklist

1. Unauthenticated `https://mail-janitor.fullstackboston.com/guide` → redirect to Authentik login
2. Authenticated user **not** in `mail-janitor-clients` → denied
3. Member of group → guided UI; connect mailbox; headers-backed workspace works
4. **End session** removes `deploy/client-sessions/<uid>/`
5. Idle wipe: set a short `MAIL_JANITOR_SESSION_TTL_HOURS` in a one-off run and confirm reaper
6. Personal MC path still FSB-skinned and gated separately

## Start / restart on fsb-01

Live personal process must run as **`fsb-agent`** (reads `profiles/yahoo/.env`). From a Cursor/agent session as `jonaldo`:

```bash
ssh -i ~/.config/fsb/agent-ssh/id_ed25519_fsb_agent -o IdentitiesOnly=yes fsb-agent@127.0.0.1 \
  'export MAIL_JANITOR_RUN_AS=fsb-agent; . /opt/fsb/config/agent/env.sh; set -a; . /opt/fsb/config/agent/cli.env; set +a; bash /opt/fsb/data/repos/mail-janitor/scripts/run-dual.sh'
```

Or already as `fsb-agent`:

```bash
bash /opt/fsb/data/repos/mail-janitor/scripts/run-dual.sh
```

Defaults from `run-dual.sh`:

- Personal: `MAIL_JANITOR_PUBLIC_BASE=/portal/mail-janitor/app`, `MAIL_JANITOR_THEME=fsb`
- Client: `MAIL_JANITOR_CLIENT_MODE=1`, empty public base, `MAIL_JANITOR_THEME=demo`, TTL 12h

## Mission Control (fsb-03 `fsb-site`)

Portal card + Authentik-gated reverse proxy for **personal** under `/portal/mail-janitor/app`.  
Client **Open** links point at the Authentik-gated subdomain; `/portal/mail-janitor/demo` redirects there.  
BFF status still polls mesh `http://100.64.0.5:8787` / `:8788` (server-side only).  
Env on `/opt/stacks/fullstackboston/.env`: `MAIL_JANITOR_PERSONAL_URL`, `MAIL_JANITOR_DEMO_URL`.

After UI/proxy changes, sync portal files to fsb-03 and `docker compose build web && docker compose up -d web` in `/opt/stacks/fullstackboston`.

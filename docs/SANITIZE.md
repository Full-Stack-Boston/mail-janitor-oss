# Release sanitize checklist

Before publishing or sharing a Mail Janitor tree (Mission Control image, zip, git push of the generic repo):

## Must not ship

- [ ] `profiles/*/.env` (app passwords)
- [ ] `profiles/*/mail.db` (mailbox index)
- [ ] `profiles/*/rules.yaml` with real keep/stage rules
- [ ] `profiles/*/audit.jsonl`, `firewall.yaml` with personal data
- [ ] `profiles/*/last_focus_batch.json` or other session files
- [ ] Personal email addresses in README, comments, scripts, fixtures

## Allowed

- [ ] `profiles/_example/` only (placeholders like `you@example.com`)
- [ ] Synthetic fixtures under `tests/`
- [ ] Provider defaults (hosts, folder names) with no account identity

## Quick checks

```bash
# From repo root
git check-ignore -v profiles/yahoo/.env profiles/yahoo/mail.db || true
rg -n 'jonaldo|@yahoo\.com|@gmail\.com' README.md docs profiles/_example scripts src || true
find profiles -name mail.db -o -name .env -o -name audit.jsonl 2>/dev/null
```

Live personalized data belongs on the Mission Control private volume, not in the public/generic git tree.

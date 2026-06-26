# /add-domain — Authoritatively add a domain to blacklist or whitelist

Add (or remove) a domain in the authoritative DynamoDB table. Use this when
you *know* a domain is malicious (and should be blocked for everyone) or
*know* it's legitimate (and should never be blocked).

This is the **authoritative** path. It's different from:
- `/clear-cached-verdict` — only flushes a stale *cached agent verdict*; the
  agent will re-investigate next time. Use when the cache is wrong, not when
  you want to override the system.
- The on-device infrastructure allowlist (`ios/Shared/DomainChecker.swift`) —
  use that for CDN / ad-tech / generic infrastructure where the right answer
  is "skip detection entirely". Ships in the next app release.

## When to use

- A specific phishing domain you confirmed manually (and threat feeds haven't
  caught it yet) — add to **blacklist**.
- A partner / customer domain that should never be flagged — add to
  **whitelist** with a `partner_id`.
- You need to *remove* an existing authoritative entry (e.g., a domain
  changed ownership).

If the domain is a CDN or ad-tech endpoint, prefer the on-device
infrastructure allowlist instead (`ios/Shared/DomainChecker.swift`). That
runs before the bloom filter and never hits the backend.

## Prerequisites

- Backend reachable (`https://api.24defend.com` for prod-dev, or
  `http://localhost:9147` for local). For local, the API key is
  `dev-api-key-change-me`; for deployed, `dev-api-key-24defend`.
- For the deployed bloom-filter regeneration step: AWS creds
  (`source /Users/mgurmendez/git/24defend-mono/aws.sh`).

## Usage

```
/add-domain blacklist phishy-thing.xyz "spotted in WhatsApp campaign 2026-05"
/add-domain whitelist brou.com.uy brou
/add-domain remove old-domain.com
```

## Commands — add to blacklist

```bash
DOMAIN="$1"
REASON="${2:-Manually added}"
API="${API_BASE:-https://api.24defend.com}"
KEY="${API_KEY:-dev-api-key-24defend}"

curl -s -X POST "${API}/admin/domains" \
  -H "X-Api-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"domains\":[\"${DOMAIN}\"],\"entry_type\":\"blacklist\",\"reason\":\"${REASON}\"}"
```

## Commands — add to whitelist

```bash
DOMAIN="$1"
PARTNER_ID="$2"   # e.g. "brou", "santander", "tonler"

curl -s -X POST "${API}/admin/domains" \
  -H "X-Api-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"domains\":[\"${DOMAIN}\"],\"entry_type\":\"whitelist\",\"partner_id\":\"${PARTNER_ID}\"}"
```

## Commands — remove

```bash
DOMAIN="$1"
curl -s -X DELETE "${API}/admin/domains/${DOMAIN}" \
  -H "X-Api-Key: ${KEY}"
```

## Verify the change took effect

```bash
# 1. Confirm via the agent's lookup path
curl -s -X POST "${API}/check" \
  -H "Content-Type: application/json" \
  -d "{\"domain\":\"${DOMAIN}\"}"
# blacklist add → verdict=block, source=blacklist
# whitelist add → verdict=allow, source=whitelist

# 2. Or read raw from DynamoDB
source /Users/mgurmendez/git/24defend-mono/aws.sh
aws dynamodb get-item \
  --table-name 24defend-domains \
  --key "{\"domain\": {\"S\": \"${DOMAIN}\"}}" \
  --region us-east-1 \
  --output json
```

## Regenerate the bloom filter

Blacklist entries land in the on-device bloom filter only after the bloom
filter is regenerated. The scheduled job runs daily (~3:00 UTC). Force it
immediately:

```bash
curl -s -X POST "${API}/admin/bloom-filter/regenerate" \
  -H "X-Api-Key: ${KEY}"

# Verify
curl -s "${API}/admin/bloom-filter/stats" -H "X-Api-Key: ${KEY}" | python3 -m json.tool
```

Devices poll the bloom filter on app start and again every few hours; expect
30+ min for a population-wide rollout.

## Difference from `/clear-cached-verdict`

| Skill | What it does | Use when |
|-------|--------------|----------|
| `/add-domain` | Writes an authoritative entry (`blacklist` / `whitelist`) | You *know* the correct verdict and want it locked in |
| `/clear-cached-verdict` | Deletes a `cache`-type entry so the agent will re-investigate | The cache is stale; the agent should retry now that you fixed the prompt / tool / allowlist |
| Infrastructure allowlist | Hardcoded set in `DomainChecker.swift`; ships with the app | CDN / ad-tech / generic infra — skip detection entirely on-device |

Don't use `/add-domain whitelist` as a workaround for a buggy agent prompt.
Fix the prompt; then `/clear-cached-verdict` for affected domains. Whitelist
is for legitimate partner / customer domains, not for false positives.

## Gotchas

### Whitelist `partner_id` is required and meaningful
`/check` returns `Verified domain (partner: <id>)` in the reason field. The
iOS app may surface this. Pick a stable, lowercase identifier.

### Blacklist entries are permanent (no TTL)
Unlike cache entries (30-day TTL), authoritative entries persist. Use sparingly
and document the reason. Threat-feed ingestion runs daily and re-adds anything
that should be there; you only need to manually add things that aren't in the
feeds.

### Bulk add
The endpoint accepts a list, not just one. To add many at once:
```bash
curl -s -X POST "${API}/admin/domains" \
  -H "X-Api-Key: ${KEY}" -H "Content-Type: application/json" \
  -d '{"domains":["a.com","b.com","c.com"],"entry_type":"blacklist","reason":"phish campaign X"}'
```

### Local vs deployed
Local backend stores in DynamoDB-local (in-memory, resets on container restart).
Deployed backend writes to the real `24defend-domains` table. Don't expect
local changes to affect prod.

### Removing a blacklist entry doesn't help if it's in the bloom filter
The bloom filter is regenerated daily from the table. If you delete a
blacklist entry, the next bloom regen drops it. Until then, devices still
match against the old bloom. Force a regen if you need it gone now (commands
above).

## Next step

If you just added a blacklist entry for an active campaign, also consider
adding the brand keyword or vocabulary to:
- `ios/Shared/BrandRuleEngine.swift`
- `ml/features.py`
- `backend/app/investigation/graph.py` (system prompt)

so the system catches the *next* variant without needing manual intervention.

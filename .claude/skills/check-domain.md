# /check-domain — Query the agent's cached verdict for a domain

Look up what the backend agent decided about a specific domain. Useful for
debugging false positives, false negatives, or understanding why the iOS
app behaved a certain way.

## When to use

- A user reports a legitimate site got blocked → check the agent verdict
- The app didn't catch a known fraud domain → check if it was ever evaluated
- You're tuning the agent prompt → see what reasoning it produced
- You suspect the agent is misclassifying a category (CDN, ad-tech, etc.)

## Prerequisites

- AWS creds active: `source /Users/mgurmendez/git/24defend-mono/aws.sh`
- Account 081856108753 (dev)

## Usage

```
/check-domain example.com
/check-domain c.ltmsphrcl.net
/check-domain oca.puntos.st
```

## Commands

```bash
DOMAIN="$1"
cd /Users/mgurmendez/git/24defend-mono
source aws.sh

# Query the DynamoDB table for this domain
aws dynamodb get-item \
  --table-name 24defend-domains \
  --key "{\"domain\": {\"S\": \"$DOMAIN\"}}" \
  --region us-east-1 \
  --output json
```

## How to read the result

The item has these fields:

| Field | Meaning |
|-------|---------|
| `entry_type` | `blacklist`, `whitelist`, or `cache` |
| `verdict` | `block`, `warn`, or `allow` |
| `confidence` | 0.0–1.0 |
| `should_notify` | true → agent recommended retroactive notification |
| `reason` | agent's free-text reasoning (block/warn cache entries only) |
| `partner_id` | only for whitelist (which bank/partner) |
| `checked_at` | ISO timestamp of investigation |
| `ttl` | epoch when DynamoDB will auto-delete the entry |

If the response is `{}` (empty Item), the domain was never investigated.
That means either:
- Nobody hit `/check` for that domain yet
- The bloom filter caught it before reaching the agent
- The infrastructure allowlist filtered it on-device (it never reached the backend)

## What to do with the result

| Verdict | Looks correct? | Action |
|---------|----------------|--------|
| block, confidence 0.9+ | Yes | Nothing |
| block, confidence 0.9+ | No (false positive) | Use `/clear-cached-verdict` and revise the agent prompt or infrastructure allowlist |
| warn | Yes (suspicious but unclear) | Nothing, agent did its job |
| allow | Yes | Nothing |
| allow | No (missed fraud) | Investigate why — check `reason` field. May need new vocabulary or new feed source |
| (empty) | — | Either bloom caught it on device or no traffic yet |

## Examples seen in production

### `cdn.thinkindot.com.cdn.cloudflare.net` (false positive — fixed)
Agent verdict: `warn`, 0.78 — "embedding cloudflare.net to impersonate a CDN endpoint". WRONG — this is a legitimate Cloudflare CDN CNAME chain. Fix was to add `cloudflare.net` to the iOS infrastructure allowlist + add ad-tech/CDN guidance to the agent prompt.

### `s1.adzonestatic.com` (false positive — fixed)
Agent verdict: `block`, 0.87 — claimed Safe Browsing flagged it. The Safe Browsing tool was broken (returned CAPTCHA HTML to server requests, the tool interpreted that as a flag). Fix was replacing the tool with Lookup API v4 + adding ad-tech to allowlist.

### `oca.puntos.st` (correct block)
Real loyalty-program phishing impersonating OCA Uruguay. Used reward/loyalty vocabulary `puntos` which wasn't in the brand rule engine until 6/5/2026.

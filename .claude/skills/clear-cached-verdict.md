# /clear-cached-verdict — Delete a cached agent verdict

Removes a domain from the DynamoDB cache so the next `/check` call triggers
a fresh agent investigation. Use after fixing the agent prompt, expanding
infrastructure allowlist, or fixing a tool — to flush stale wrong verdicts.

## When to use

- Agent classified a legitimate domain as fraud and you fixed the root cause
  (prompt change, allowlist addition, tool fix). The cache still has the
  wrong verdict (30-day TTL) so the next user hitting it gets the old result.
- You want to re-investigate after improving the agent's tools or context.
- A domain was flagged by a broken tool (e.g., the old Safe Browsing tool).

## ⚠️ Don't use this to whitelist

If a domain is legitimately wrong-blocked and you want to permanently fix it:
- Add it to `infrastructureSet` in `ios/Shared/DomainChecker.swift` (CDNs,
  ad-tech, common services)
- Or add it as a `whitelist` entry via `POST /admin/domains`
- Don't just delete the cache entry — the next investigation might produce
  the same wrong verdict if the underlying cause isn't fixed.

## Prerequisites

- AWS creds active: `source /Users/mgurmendez/git/24defend-mono/aws.sh`

## Usage

```
/clear-cached-verdict example.com
/clear-cached-verdict c.ltmsphrcl.net
```

## Commands

```bash
DOMAIN="$1"
cd /Users/mgurmendez/git/24defend-mono
source aws.sh

# 1. First check what's currently cached (optional but recommended)
echo "Current cached verdict:"
aws dynamodb get-item \
  --table-name 24defend-domains \
  --key "{\"domain\": {\"S\": \"$DOMAIN\"}}" \
  --region us-east-1 \
  --query 'Item.{verdict: verdict.S, confidence: confidence.S, reason: reason.S, type: entry_type.S}' \
  --output json

# 2. Confirm with user before deleting (mental check, not automated)

# 3. Delete the entry
aws dynamodb delete-item \
  --table-name 24defend-domains \
  --key "{\"domain\": {\"S\": \"$DOMAIN\"}}" \
  --region us-east-1

echo "Deleted cache entry for $DOMAIN. Next /check call will re-investigate."
```

## Bulk clear (multiple domains)

```bash
for d in domain1.com domain2.com domain3.com; do
  aws dynamodb delete-item \
    --table-name 24defend-domains \
    --key "{\"domain\": {\"S\": \"$d\"}}" \
    --region us-east-1
  echo "Cleared $d"
done
```

## ⚠️ Don't delete blacklist or whitelist entries

This command is intended for `entry_type=cache` entries (agent investigations).
If you delete a `blacklist` or `whitelist` entry, the domain stops being
authoritatively known. Use `/check-domain` first to verify the entry type.

If you really need to remove a blacklist/whitelist entry, use:
```bash
curl -X DELETE https://api.24defend.com/admin/domains/<domain> \
  -H "X-Api-Key: dev-api-key-24defend"
```

## Historical record

The 5 entries cleared on 2026-05-07 after the CDN/ad-tech fix:
- cdn.thinkindot.com.cdn.cloudflare.net
- c.ltmsphrcl.net
- s1.adzonestatic.com
- cdn.jsdelivr.net.cdn.cloudflare.net
- api.id.thinkindot.com.cdn.cloudflare.net

Root cause was the broken Safe Browsing tool returning false positives for
every domain. After fixing the tool and adding ad-tech/CDN context to the
agent prompt, these entries needed to be cleared so re-investigation could
produce correct verdicts.

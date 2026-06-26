# /ingest-now — Trigger threat-feed ingestion manually

Fire the blacklist ingestion job on demand instead of waiting for the daily
schedule (~3:00 UTC). Pulls from OpenPhish, PhishTank, URLhaus (abuse.ch),
and Phishing.Army, filters out Majestic Million top-100K base domains, then
writes blacklist entries to DynamoDB.

## When to use

- You just deployed and want a fresh blacklist immediately (don't wait for 3:00 UTC)
- A specific feed source seems stale and you want to force a refresh
- You bumped the ingestion logic (`backend/app/ingestion/runner.py`) and want
  to verify it end-to-end against live feeds
- Debugging "why didn't this domain get blocked?" — check feed coverage

## Prerequisites

- Backend deployed and healthy. Check first with `/status`.
- Admin API key (`dev-api-key-24defend` for deployed).
- AWS creds active for the regeneration and verification steps:
  `source /Users/mgurmendez/git/24defend-mono/aws.sh`

## Usage

```
/ingest-now              # trigger ingestion against deployed API
/ingest-now local        # trigger against http://localhost:9147
```

## Commands

```bash
API="${API_BASE:-https://api.24defend.com}"
KEY="${API_KEY:-dev-api-key-24defend}"

# 1. Fire the ingestion job. It runs in the background — the request returns
#    fast but the actual work takes several minutes (feed fetch + filter +
#    DynamoDB bulk write). The ALB has a 60-second idle timeout, so we
#    --max-time the curl and ignore the response.
echo "Kicking off ingestion..."
curl -s --max-time 5 -X POST "${API}/admin/ingest/blacklists" \
  -H "X-Api-Key: ${KEY}" || echo "(timeout expected — job runs in background)"

# 2. Tail the backend logs to watch progress
#    (uses the /logs-backend skill convention)
source /Users/mgurmendez/git/24defend-mono/aws.sh
LOG_GROUP=$(aws logs describe-log-groups --region us-east-1 \
  --query "logGroups[?contains(logGroupName, 'defend-dev')].logGroupName" \
  --output json | python3 -c "import sys,json; print(json.load(sys.stdin)[-1])")

# Look for the markers (uppercase WARNING so they stand out in CloudWatch)
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --region us-east-1 \
  --filter-pattern '?"INGESTION START" ?"INGESTION DONE" ?"INGESTION FAILED" ?"PhishTank" ?"OpenPhish" ?"URLhaus" ?"Phishing.Army"' \
  --max-items 50 \
  --query 'events[].message' --output text
```

## Expected progress markers (in order)

| Marker | What just happened |
|--------|--------------------|
| `INGESTION START: fetching public threat feeds...` | Job kicked off |
| `PhishTank: N unique domains` | PhishTank feed parsed |
| `OpenPhish: N unique domains` | OpenPhish feed parsed |
| `URLhaus: N unique domains` | URLhaus feed parsed |
| `Phishing.Army: N unique domains` | Phishing.Army feed parsed |
| `Majestic Million: filtered out X candidates` | Top-100K filter ran |
| `INGESTION DONE: {...}` | Stats dict logged |

A clean run should land somewhere around 70K+ unique domains after dedup
and Majestic filtering. If you see far fewer, one of the feeds failed
(check the per-feed lines for warnings).

## Verify the final state

```bash
# 1. Total count in the domains table (full scan — slow but informative)
aws dynamodb scan --table-name 24defend-domains \
  --region us-east-1 --select COUNT --output json \
  --query '{total: ScannedCount}'

# 2. Bloom filter stats (regen runs automatically after ingestion)
curl -s "${API}/admin/bloom-filter/stats" -H "X-Api-Key: ${KEY}" | python3 -m json.tool

# Look for: last_regenerated within the last few minutes, item_count consistent
# with the scan result, blacklist file size in KB > 100 (a healthy bloom is
# typically ~127 KB for ~72K entries).
```

## Force a bloom filter regen separately

Ingestion triggers a bloom regen automatically. If you want to force one
without re-ingesting (e.g., after manual `/add-domain` calls):

```bash
curl -s -X POST "${API}/admin/bloom-filter/regenerate" \
  -H "X-Api-Key: ${KEY}"
```

## Expected timing

| Step | Typical duration |
|------|------------------|
| PhishTank | 10-30s |
| OpenPhish | 5-10s |
| URLhaus | 10-20s |
| Phishing.Army | 5-15s |
| Majestic Million download | 30-60s (15 MB CSV) |
| DynamoDB bulk write | 30-90s (batches of 25) |
| Bloom regen + S3 upload | 5-10s |

Total: roughly **3–5 minutes** end to end. If it's still running after 10
minutes, something's stuck — check logs for stack traces.

## Gotchas

### ALB 60-second idle timeout
The endpoint returns fast because ingestion runs as a background asyncio task.
Don't wait for the HTTP response — it'll time out. Just monitor logs.

### Feed sources sometimes 5xx or rate-limit
PhishTank in particular has been known to return 503 during peak hours. The
runner logs per-feed warnings and continues with the others — partial ingest
is fine. Re-run later for full coverage.

### Majestic Million download fails
If the download fails, the runner falls back to a hardcoded `SHARED_INFRASTRUCTURE_DOMAINS`
set of 43 domains (see `backend/app/ingestion/runner.py`). The fallback is
much smaller, so you'll see more "shared infrastructure" domains (CDN endpoints,
ad-tech) reaching the bloom filter than usual. Re-run the ingest when the
Majestic source recovers.

### Domain count goes DOWN after ingestion
That's normal if the previous ingestion grabbed more aggressive feeds that
have since cleaned up their lists. Compare against `/admin/bloom-filter/stats`
from before and after to see real delta.

### Local ingestion is slow / can be skipped
Running this against `http://localhost:9147` works, but the DynamoDB-local
backing store resets on container restart. Don't bother seeding 70K domains
locally — the `seed.py` script gives you a tiny representative set instead.

## Next step

After ingestion finishes:
1. `/status` — verify bloom-filter stats look healthy
2. If you were debugging a specific missing domain, `/check-domain <d>` to
   confirm it's now in the database
3. If you added authoritative entries via `/add-domain` and then ran an
   ingest, run a fresh `/admin/bloom-filter/regenerate` to be sure everything
   was included

# /status — Quick health summary

One-shot snapshot of the system: API reachable, ECS task running, bloom
filter freshness, recent agent activity, DNS resolving. Use as a morning
sanity check or before/after a deploy.

## Usage

```
/status
```

## What it checks

| Check | What it tells you |
|-------|-------------------|
| API `/health` | Backend container is up and responsive |
| `/admin/bloom-filter/stats` | Bloom filters are loaded, last regen time |
| DNS for api.24defend.com | Route 53 / GoDaddy DNS is resolving |
| DNS for www.24defend.com | CloudFront alias is resolving |
| ECS service running count | At least one task is actually running |
| Latest CloudWatch log | Most recent log line (sanity check there's any activity) |
| Domain count by type | How many blacklist/whitelist/cache entries in DynamoDB |

## Commands

```bash
cd /Users/mgurmendez/git/24defend-mono
source aws.sh

echo "=== 24Defend Status ==="
echo ""

# 1. API health
echo "--- API /health ---"
curl -s -m 5 -w "  HTTP %{http_code}, %{time_total}s\n" \
  https://api.24defend.com/health -o /dev/null || echo "  FAIL"
echo ""

# 2. Bloom filter stats
echo "--- Bloom filter stats ---"
curl -s -m 5 https://api.24defend.com/admin/bloom-filter/stats \
  -H "X-Api-Key: dev-api-key-24defend" | python3 -m json.tool 2>/dev/null \
  || echo "  FAIL"
echo ""

# 3. DNS resolution
echo "--- DNS ---"
for h in api.24defend.com www.24defend.com 24defend.com; do
  IP=$(dig +short +time=2 +tries=1 "$h" A | head -1)
  echo "  $h → ${IP:-NXDOMAIN}"
done
echo ""

# 4. ECS service
echo "--- ECS service ---"
aws ecs describe-services \
  --cluster defend-dev-cluster \
  --services defend-dev-backend \
  --region us-east-1 \
  --query 'services[0].{desired: desiredCount, running: runningCount, pending: pendingCount, status: status, lastDeploy: deployments[0].createdAt}' \
  --output json
echo ""

# 5. Latest log line
echo "--- Latest log ---"
LOG_GROUP=$(aws logs describe-log-groups --region us-east-1 \
  --query "logGroups[?contains(logGroupName, 'defend-dev')].logGroupName" \
  --output json | python3 -c "import sys,json; print(json.load(sys.stdin)[-1])")
STREAM=$(aws logs describe-log-streams \
  --log-group-name "$LOG_GROUP" \
  --region us-east-1 \
  --order-by LastEventTime --descending --limit 1 \
  --query 'logStreams[0].logStreamName' --output text)
aws logs get-log-events \
  --log-group-name "$LOG_GROUP" \
  --log-stream-name "$STREAM" \
  --region us-east-1 \
  --query 'events[-1].message' --output text
echo ""

# 6. DynamoDB counts (full scan, slow — only for dev table)
echo "--- DynamoDB counts ---"
aws dynamodb scan --table-name 24defend-domains \
  --region us-east-1 \
  --select COUNT \
  --output json \
  --query '{total: ScannedCount}'
# Note: filtering by entry_type requires a full scan; expensive. Skip for prod.
echo ""

# 7. ECR latest image push time
echo "--- ECR latest image ---"
aws ecr describe-images \
  --repository-name defend-dev-backend \
  --image-ids imageTag=latest \
  --region us-east-1 \
  --query 'imageDetails[0].{pushed: imagePushedAt, digest: imageDigest}' \
  --output json
```

## Interpreting the output

### Healthy state

- `HTTP 200` on /health
- bloom filter stats showing recent timestamp (within last 24h for daily regen)
- DNS resolves to a CloudFront IP for www, an ALB IP for api
- ECS `running` = `desired` (typically 1 in dev)
- Latest log line is recent and not an error
- DynamoDB count > 70K (blacklist alone is ~70K)
- ECR image pushed within last few days

### Warning signs

- /health returns 503 → container started but is unhealthy (check logs)
- /health returns curl error → ALB or DNS issue
- bloom filter stats shows no `last_regenerated` or stale (> 48h) → scheduler not running
- DNS NXDOMAIN → DNS misconfiguration at GoDaddy
- ECS `running` < `desired` → tasks failing to start (check logs and task definition)
- DynamoDB count very low → ingestion not running or table was wiped
- ECR latest pushed days ago and code has changed → forgot to deploy

## Optional flags / extensions

If used often, this skill can be extended to:
- Check Bedrock service quota
- Check Secrets Manager values are present
- Test the `/check` endpoint with a known phishing domain to verify the agent works end-to-end

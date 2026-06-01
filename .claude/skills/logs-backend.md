# /logs-backend — Tail backend container logs

Pulls recent logs from the ECS task running the backend. Use for debugging
production issues, watching ingestion progress, or seeing agent investigations
in real time.

## When to use

- After `/deploy-backend-fast` to verify the new container started cleanly
- Debugging 500 errors reported by the iOS app
- Watching the agent investigate a domain in real time
- Verifying the daily ingestion job ran (3:00 UTC)
- Checking why a `/check` response is slow

## Prerequisites

- AWS creds active: `source /Users/mgurmendez/git/24defend-mono/aws.sh`

## Usage

```
/logs-backend           # last 100 lines from latest log stream
/logs-backend 200       # last 200 lines
/logs-backend tail      # tail / follow latest stream
/logs-backend errors    # last 100 lines, filtered to errors/warnings
```

## Commands — last N lines from the latest log stream

```bash
N="${1:-100}"
cd /Users/mgurmendez/git/24defend-mono
source aws.sh

# 1. Find the log group (CDK creates it with a hash suffix)
LOG_GROUP=$(aws logs describe-log-groups --region us-east-1 \
  --query "logGroups[?contains(logGroupName, 'defend-dev')].logGroupName" \
  --output json | python3 -c "import sys,json; print(json.load(sys.stdin)[-1])")

# 2. Find the most recent log stream
STREAM=$(aws logs describe-log-streams \
  --log-group-name "$LOG_GROUP" \
  --region us-east-1 \
  --order-by LastEventTime --descending --limit 1 \
  --query 'logStreams[0].logStreamName' --output text)

# 3. Tail it
aws logs get-log-events \
  --log-group-name "$LOG_GROUP" \
  --log-stream-name "$STREAM" \
  --region us-east-1 \
  --query "events[-${N}:].message" \
  --output text
```

## Commands — filter to errors and warnings

```bash
# Same setup as above, then:
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --region us-east-1 \
  --filter-pattern '?ERROR ?Error ?error ?WARNING ?Warning ?Exception ?Traceback' \
  --max-items 100 \
  --query 'events[].message' --output text
```

## Commands — search by string

```bash
# e.g., find all investigations for a specific domain
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --region us-east-1 \
  --filter-pattern '"cdn.thinkindot.com"' \
  --max-items 50 \
  --query 'events[].message' --output text
```

## Commands — follow live (poor man's tail -f)

```bash
# AWS CLI doesn't have native follow; loop with sleep
while true; do
  LAST_TS=$(date +%s -d "1 minute ago")000
  aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --region us-east-1 \
    --start-time $LAST_TS \
    --query 'events[].message' --output text
  sleep 30
done
```

## Common patterns to grep for

| Pattern | Meaning |
|---------|---------|
| `Investigation for <domain> completed in Ns` | Agent finished investigating |
| `Starting LangGraph investigation for` | Agent started new investigation |
| `Domain age:` | RDAP tool returned (slow domain age check) |
| `Safe Browsing` | Safe Browsing tool fired |
| `Bloom filter regenerated` | Daily bloom job completed |
| `Ingestion completed` | Daily blacklist ingestion completed |
| `429` | Rate limited (typically Bedrock) |
| `503` | Service overload |
| `Bedrock` | LLM call (look for token usage and cost) |

## Gotchas

### Logs older than a few days are gone
CloudWatch Logs retention is set to 30 days for dev (longer for prod via
the CDK stack). Don't expect to find evidence of an incident from last month.

### Log group name has a hash
CDK appends a hash to the log group name. Always look it up dynamically
(as in step 1) rather than hardcoding.

### Stream rotates per task
ECS rotates log streams as tasks rotate. The "latest" stream may only have
data since the last redeploy. To find logs across redeploys, use
`filter-log-events` against the log GROUP rather than `get-log-events`
against a specific stream.

### Bedrock noise
The LangChain Bedrock client logs every retry. If you see repeated
"Retrying..." messages, the LLM is being rate-limited — usually transient.

# /deploy — Deploy 24Defend backend to AWS

Deploy the backend to AWS using CDK. Supports dev and prod environments.

## Usage

```
/deploy              # deploy to dev (default)
/deploy dev          # deploy to dev explicitly
/deploy prod         # deploy to prod
```

## Prerequisites

- AWS credentials in `aws.sh` (project root) — these are IAM user keys, NOT SSO session tokens
- Serper API key in `serper.conf` (project root)
- CDK CLI installed (`npm install -g aws-cdk`)
- Docker running (for building the container image)

## Known gotchas

### 1. Docker platform mismatch (ARM vs AMD64)
The Dockerfile MUST have `FROM --platform=linux/amd64` because Fargate runs AMD64 but Macs are ARM.
The CDK stack uses `platform=cdk.aws_ecr_assets.Platform.LINUX_AMD64`. Cross-compilation is slower
but required. If you see `exec format error` in ECS logs, this is the cause.

### 2. CDK image caching
CDK computes a hash of the `backend/` directory to decide whether to rebuild the Docker image.
If you change code but CDK doesn't detect it (e.g., only .pyc files changed), add a comment to
the Dockerfile to force a new hash: `# Force rebuild: <date>`.

### 3. Secrets Manager must be populated BEFORE container starts
The Fargate task pulls secrets from Secrets Manager on startup. If secrets are empty, the container
starts but the env vars are empty strings. Set secrets IMMEDIATELY after stack creation, before the
ECS service tries to launch the first task.

### 4. DynamoDB table is CDK-managed
The `ensure_table()` function in `db.py` skips table creation when `DEFEND_DYNAMODB_ENDPOINT` is
not set (production). If you see `ListTables AccessDeniedException`, the container is running old
code that still tries to create the table. Force a new deployment with a fresh Docker image.

### 5. ECS service stuck in CREATE_IN_PROGRESS
If the container crashes repeatedly (wrong image arch, missing secrets, bad permissions), the
CloudFormation stack gets stuck in CREATE_IN_PROGRESS for up to 30 minutes. You cannot update
a stack in this state. Options:
- Wait for it to fail/rollback (up to 30 min)
- Delete the stack: `aws cloudformation delete-stack --stack-name defend-dev --region us-east-1`
- After delete, clean up retained resources (ECR repo, S3 bucket) before redeploying

### 6. Retained resources block redeploy
ECR repo and S3 bucket use RETAIN policy in prod (DESTROY in dev). If you delete and recreate
the stack, these orphaned resources block creation. Delete them first:
```bash
aws ecr delete-repository --repository-name defend-dev-backend --region us-east-1 --force
aws s3 rb s3://24defend-bloomfilter-dev --force --region us-east-1
```

### 7. ALB idle timeout
The ALB has a 60-second idle timeout. Long-running requests (blacklist ingestion, agent investigation)
may time out at the ALB level even though they complete server-side. The scheduler runs internally
with no timeout issues. For manual triggers, fire and forget — don't wait for the response.

### 8. Startup ingestion runs in background
The blacklist ingestion + bloom generation runs as a background `asyncio.create_task()` on startup.
It does NOT block the server from starting. Check bloom-filter/stats to see if it completed.

## Commands

```bash
# 1. Load credentials
cd ~/git/24defend-mono
source aws.sh
export DEFEND_SERPER_API_KEY=$(cat serper.conf 2>/dev/null || echo "")
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1

# 2. Set environment
export DEFEND_ENV="${1:-dev}"

# 3. Install CDK dependencies
cd infra
pip3 install -q -r requirements.txt 2>/dev/null

# 4. Bootstrap (first time per account — safe to rerun)
cdk bootstrap aws://$(aws sts get-caller-identity --query Account --output text)/us-east-1

# 5. Clean build artifacts (avoids stale image cache)
rm -rf cdk.out

# 6. Deploy
echo "Deploying 24Defend backend to $DEFEND_ENV..."
cdk deploy --all --require-approval never

# 7. Set secrets (MUST do before container starts — do immediately after deploy)
aws secretsmanager put-secret-value \
  --secret-id "defend-${DEFEND_ENV}/api-key" \
  --secret-string "dev-api-key-24defend" \
  --region us-east-1

aws secretsmanager put-secret-value \
  --secret-id "defend-${DEFEND_ENV}/serper-api-key" \
  --secret-string "$(cat ~/git/24defend-mono/serper.conf)" \
  --region us-east-1

# 8. Verify health
sleep 30
curl -s http://api.24defend.com/health

# 9. Check bloom filter stats (startup ingestion may still be running)
curl -s http://api.24defend.com/admin/bloom-filter/stats \
  -H "X-Api-Key: dev-api-key-24defend"

# 10. Seed Uruguay whitelist (if first deploy)
cd ~/git/24defend-mono/backend
DEFEND_API_KEY=dev-api-key-24defend python3 scripts/seed_uruguay.py http://api.24defend.com
```

## DNS (GoDaddy)

After deploy, add CNAME records:

| Type  | Name | Value                                                              |
|-------|------|--------------------------------------------------------------------|
| CNAME | api  | defend-Servi-OhtdcsYGDV6K-995646675.us-east-1.elb.amazonaws.com   |
| CNAME | cdn  | d3vs8fd6gden8.cloudfront.net                                       |

## Troubleshooting

### Check container logs
```bash
source aws.sh
LOG_GROUP=$(aws logs describe-log-groups --region us-east-1 \
  --query "logGroups[?contains(logGroupName, 'defend')].logGroupName" \
  --output json | python3 -c "import sys,json; print(json.load(sys.stdin)[-1])")
STREAM=$(aws logs describe-log-streams --log-group-name "$LOG_GROUP" \
  --region us-east-1 --order-by LastEventTime --descending --limit 1 \
  --query 'logStreams[0].logStreamName' --output text)
aws logs get-log-events --log-group-name "$LOG_GROUP" --log-stream-name "$STREAM" \
  --region us-east-1 --query 'events[-20:].message' --output text
```

### Force new ECS deployment (without CDK redeploy)
```bash
aws ecs update-service --cluster defend-dev-cluster --service defend-dev-backend \
  --force-new-deployment --region us-east-1
```

### Manually trigger blacklist ingestion
```bash
curl -s --max-time 5 -X POST http://api.24defend.com/admin/ingest/blacklists \
  -H "X-Api-Key: dev-api-key-24defend"
# Don't wait for response — ALB times out at 60s but job runs server-side
```

### Manually trigger bloom filter regeneration
```bash
curl -s -X POST http://api.24defend.com/admin/bloom-filter/regenerate \
  -H "X-Api-Key: dev-api-key-24defend"
```

### Check stack status
```bash
aws cloudformation describe-stacks --stack-name defend-dev --region us-east-1 \
  --query "Stacks[0].StackStatus" --output text
```

### Nuclear option: delete everything and start fresh
```bash
aws cloudformation delete-stack --stack-name defend-dev --region us-east-1
# Wait for delete to complete, then:
aws ecr delete-repository --repository-name defend-dev-backend --region us-east-1 --force
aws s3 rb s3://24defend-bloomfilter-dev --force --region us-east-1
# Then redeploy from step 5
```

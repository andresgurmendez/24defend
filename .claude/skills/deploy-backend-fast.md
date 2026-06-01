# /deploy-backend-fast — Backend deploy without CDK

Fast path for backend code-only changes. Skips CDK synth, builds the Docker
image locally, pushes to ECR, and forces a new ECS deployment. Takes ~2 min
vs `/deploy`'s ~5 min.

## When to use

- You changed Python code in `backend/app/` (routes, agent prompt, tools, models)
- You changed `backend/requirements.txt` (still needs Docker rebuild but no infra)
- You did NOT change anything in `infra/`, environment variables, IAM, or secrets

If infrastructure changed, use `/deploy` instead.

## Why this exists

GitHub Actions CI is broken (missing `AWS_DEPLOY_ROLE_ARN` secret). And full
CDK deploy is overkill for code-only iteration. This skill is the day-to-day
"push code to prod" command.

## Prerequisites

- Docker Desktop running
- AWS creds active: `source /Users/mgurmendez/git/24defend-mono/aws.sh`
  (these are static IAM keys for account 081856108753, bedrock24defend user)

## Usage

```
/deploy-backend-fast              # deploy to dev (default)
/deploy-backend-fast dev          # explicit dev
/deploy-backend-fast prod         # prod
```

## Commands

```bash
ENV="${1:-dev}"
ACCOUNT="081856108753"
REGION="us-east-1"
ECR_REPO="defend-${ENV}-backend"
ECR_REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"

cd /Users/mgurmendez/git/24defend-mono
source aws.sh

# 1. Verify AWS creds active and on correct account
aws sts get-caller-identity --query Account --output text
# Must print 081856108753 (dev) or the prod account ID

# 2. Bump Dockerfile rebuild comment to force fresh hash
SHORT_SHA=$(git rev-parse --short HEAD)
DATE=$(date +%Y-%m-%d)
# (manually edit backend/Dockerfile, change "# Force rebuild: ..." line)

# 3. ECR login
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ECR_REGISTRY

# 4. Build for AMD64 (Fargate platform — Macs are ARM)
docker build --platform linux/amd64 \
  -t $ECR_REGISTRY/$ECR_REPO:latest \
  -t $ECR_REGISTRY/$ECR_REPO:$SHORT_SHA \
  backend/

# 5. Push both tags
docker push $ECR_REGISTRY/$ECR_REPO:latest
docker push $ECR_REGISTRY/$ECR_REPO:$SHORT_SHA

# 6. Force ECS service to pull the new image
aws ecs update-service \
  --cluster defend-${ENV}-cluster \
  --service defend-${ENV}-backend \
  --force-new-deployment \
  --region $REGION \
  --query 'service.{status: status, desiredCount: desiredCount, runningCount: runningCount}' \
  --output json

# 7. Wait for rollout (optional — usually ~2 min)
echo "Waiting for service to stabilize..."
aws ecs wait services-stable \
  --cluster defend-${ENV}-cluster \
  --services defend-${ENV}-backend \
  --region $REGION

# 8. Verify
curl -s https://api.24defend.com/health
```

## Gotchas

### Docker still uses cached layer despite code change
The `COPY app/ app/` layer changes only when files change. If the issue is
only in `requirements.txt` or you suspect caching weirdness, bump the
`# Force rebuild: YYYY-MM-DD` comment in `backend/Dockerfile`.

### ARM vs AMD64
Always use `--platform linux/amd64`. Without it the image runs locally but
fails on Fargate with `exec format error`. Look for the FROM line:
`FROM --platform=linux/amd64 python:3.12-slim`.

### Service stuck
If `aws ecs wait` hangs or the service can't stabilize, check the running tasks:
```bash
aws ecs list-tasks --cluster defend-dev-cluster --service-name defend-dev-backend \
  --region us-east-1
aws ecs describe-tasks --cluster defend-dev-cluster --tasks <task-arn> \
  --region us-east-1 \
  --query 'tasks[0].containers[0].{lastStatus: lastStatus, exitCode: exitCode, reason: reason}'
```
Common causes: bad env var, secret missing, container can't talk to DynamoDB.

### After deploy, container still serving old code
ECS draining can take 30-60s. The ALB sends traffic to whatever target is
healthy. If you're getting both responses, wait for the deployment to complete
fully (`aws ecs wait` does this).

## Container name pattern

The running container is named `orbit-dev_orbit-backend.1.<hash>` style in
some places. For 24defend the service is `defend-dev-backend` and the task
name is whatever ECS assigns. Find it with:
```bash
aws ecs list-tasks --cluster defend-dev-cluster --service-name defend-dev-backend \
  --region us-east-1 --query 'taskArns[0]' --output text
```

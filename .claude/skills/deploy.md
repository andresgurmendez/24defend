# /deploy — Deploy 24Defend backend to AWS

Deploy the backend to AWS using CDK. Supports dev and prod environments.

## Usage

```
/deploy              # deploy to dev (default)
/deploy dev          # deploy to dev explicitly
/deploy prod         # deploy to prod
```

## Steps

1. Source AWS credentials from `aws.sh` in the project root
2. Source Serper API key from `serper.conf` if present
3. Bootstrap CDK if this is the first deploy to the account
4. Build Docker image and deploy CDK stack
5. Seed DynamoDB with Uruguay institution whitelist data
6. Report the ALB URL for DNS configuration

## Commands

```bash
# Load credentials
cd ~/git/24defend-mono
source aws.sh
export DEFEND_SERPER_API_KEY=$(cat serper.conf 2>/dev/null || echo "")

# Set environment (default: dev)
export DEFEND_ENV="${1:-dev}"

# Install CDK dependencies if needed
cd infra
pip3 install -q -r requirements.txt 2>/dev/null

# Bootstrap (first time only — safe to run again)
cdk bootstrap --quiet 2>/dev/null || true

# Deploy
echo "Deploying 24Defend backend to $DEFEND_ENV..."
cdk deploy --all --require-approval never

# Show outputs
echo ""
echo "=== Deployment Complete ==="
echo "Environment: $DEFEND_ENV"
cdk outputs 2>/dev/null || true

# Seed Uruguay whitelist data
cd ~/git/24defend-mono/backend
echo ""
echo "Seeding Uruguay institution data..."
# Get the ALB URL from CDK outputs and use it for seeding
# For now, remind the user to seed manually after first deploy
echo ""
echo "Next steps:"
echo "1. Set secrets in AWS Secrets Manager:"
echo "   aws secretsmanager put-secret-value --secret-id defend-${DEFEND_ENV}-api-key --secret-string 'your-api-key'"
echo "   aws secretsmanager put-secret-value --secret-id defend-${DEFEND_ENV}-serper-key --secret-string '$(cat ~/git/24defend-mono/serper.conf)'"
echo "2. Create CNAME record: api.24defend.com -> <ALB DNS from output above>"
echo "3. Run seed script: python3 scripts/seed_uruguay.py https://api.24defend.com"
```

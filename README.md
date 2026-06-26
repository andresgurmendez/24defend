# 24Defend

Anti-phishing link protection for iOS. DNS-level interception via NetworkExtension, on-device bloom filter and ML classifier, AWS Bedrock-backed investigation agent for unknown domains. Operated by **TONLER S.A.S.** (Uruguay).

## Quick start (new dev)

```bash
git clone <repo>                          # uses github-24defend SSH alias — see ONBOARDING.md
cp aws.sh.example aws.sh                  # then fill in dev IAM keys; see docs/aws-keys.md
source aws.sh                             # AWS creds (request from tech lead via secure channel)
cd backend && docker compose up --build   # API at http://localhost:9147, docs /docs
```

Full first-day setup: see [ONBOARDING.md](ONBOARDING.md). AWS keys (setup, rotation, security): [docs/aws-keys.md](docs/aws-keys.md). Run `/onboard-new-dev` from Claude Code to self-verify your environment.

## Repository layout

| Path | Purpose | README |
|------|---------|--------|
| `ios/` | SwiftUI app + NetworkExtension packet tunnel | [ios/DISTRIBUTION.md](ios/DISTRIBUTION.md) |
| `backend/` | FastAPI (Python 3.12), DynamoDB, Bedrock, LangGraph agent | [backend/README.md](backend/README.md) |
| `ml/` | Lightweight domain classifier training pipeline | [ml/README.md](ml/README.md) |
| `infra/` | AWS CDK (Fargate, ALB, DynamoDB, ECR, S3, Secrets Manager) | — |
| `www/` | Marketing site + privacy policies (S3 + CloudFront) | — |
| `research/` | Technical analyses, backlog, attack-pattern docs | [research/improvements.md](research/improvements.md) |
| `.claude/skills/` | Claude Code slash commands for ops tasks | — |

## Key docs

- **[ONBOARDING.md](ONBOARDING.md)** — first day / first week guide
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — branch / commit / PR / testing conventions
- **[architecture.md](architecture.md)** — full system architecture (~900 lines)
- **[docs/architecture-diagram.md](docs/architecture-diagram.md)** — visual overview (60-second read)
- **[docs/aws-keys.md](docs/aws-keys.md)** — AWS credential setup, rotation, security
- **[docs/troubleshooting.md](docs/troubleshooting.md)** — common errors and fixes
- **[CLAUDE.md](CLAUDE.md)** — project patterns, legal entity, deployment notes
- **[CHANGELOG.md](CHANGELOG.md)** — dated history of changes
- **[research/improvements.md](research/improvements.md)** — backlog / known issues

## Claude Code skills

This repo ships slash commands for common ops. See `.claude/skills/`:

| Skill | Purpose |
|-------|---------|
| `/local-dev` | Bring up the local stack (backend + iOS sim) |
| `/test-backend` | Run / write pytest |
| `/ios-build` | Regenerate xcodeproj, build, run tests from CLI |
| `/onboard-new-dev` | Verify your environment (AWS / Docker / venv / repo) |
| `/deploy-backend-fast` | Fast ECS code-only redeploy |
| `/deploy` | Full CDK deploy (infra changes) |
| `/deploy-www` | Sync `www/` to S3 + invalidate CloudFront |
| `/status` | One-shot health snapshot |
| `/logs-backend` | Tail / filter CloudWatch logs |
| `/check-domain` | Read cached agent verdict |
| `/clear-cached-verdict` | Flush a stale verdict |
| `/add-domain` | Add to blacklist / whitelist authoritatively |
| `/ingest-now` | Trigger feed ingestion manually |

## Help

Public contact: `dev@24defend.com`. For internal team channels (Slack, on-call rotation), ask the Tech Lead during onboarding.

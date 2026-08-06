# Separate dev and prod environments (v2 — clean-prod / DNS-cutover direction)

## Context

`infra/config.py` already has the *shape* of a dev/prod split (`ENVIRONMENTS["dev"]` / `["prod"]`), but it's broken and never finished:

- Both entries point at the same `api_domain` (`api.24defend.com`).
- `prod.account` is still `"PLACEHOLDER"` — a real `cdk deploy` with `DEFEND_ENV=prod` would fail immediately.
- The only stack ever deployed is `defend-dev` (confirmed via `infra/cdk.out`, which only has `defend-dev.*` artifacts). **`defend-dev` is the stack currently serving `api.24defend.com`, the real website (`24defend-www-dev` bucket), and the just-added metrics dashboard.** There is no real dev environment today — "dev" is prod wearing a dev label.
- Every physical AWS resource name is derived directly from `env_name` (`prefix = f"defend-{env_name}"`, bucket names interpolate `env_name` directly). Naively renaming the dict key from `"dev"` to `"prod"` would make CDK recreate the ECS service/ALB (→ DNS cutover + downtime), Secrets Manager secrets (→ manual re-entry), and the ECR repo (→ lost image, deploy tooling breaks).
- The DynamoDB table name (`24defend-domains`) is hardcoded with no env suffix — a second stack deployed as-is would collide on it.
- Every `.claude/skills/*.md` deploy script hardcodes `defend-dev`/`24defend-*-dev`/`api.24defend.com` directly in bash — they don't read `infra/config.py`.
- `frontend/vite.config.ts`'s dev proxy hardcodes `target: 'https://api.24defend.com'` — local frontend dev currently talks to real production data.
- No `frontend/.env.development` / `.env.production` exist yet.

### Revised decision (v2)

An earlier version of this plan treated the currently-live stack as "prod" (logically, keeping its `defend-dev` physical name frozen forever) and stood up a throwaway `defend-sandbox` for dev. **That direction is superseded.**

Key fact that changes the calculus: **there are no real end users yet.** Per `ios/DISTRIBUTION.md`, distribution today is TestFlight-internal only (same App Store Connect team, ≤100 testers, **no Apple review**, builds installed manually via the TestFlight app). Nothing has gone through public App Store review. This means:

- The app's hardcoded `baseURL` (`ios/Shared/APIClient.swift:19`, `https://api.24defend.com`) doesn't need to change — a DNS-level cutover behind that same hostname is invisible to the app.
- There's no large, unreachable user base that would be stranded by a brief cutover window — just a handful of internal testers who can be given a heads-up.
- It's worth paying a one-time migration cost now to get **physical names permanently aligned with logical names** (`defend-prod` = prod, `defend-dev` = dev), instead of living forever with the confusing "prod is secretly named defend-dev" indirection the v1 plan required.

**New direction:** build a brand-new, clean `defend-prod` stack (fresh ECR/cluster/ALB/ACM cert/secrets, real AWS account, real `api.24defend.com` eventually pointed at it), seed it with real blacklist data via the existing ingestion pipeline, smoke-test it on its own ALB DNS name, then do a single low-risk DNS cutover of `api.24defend.com` from the old stack's ALB to the new one. The existing stack — still physically `defend-dev` — keeps running as-is and is *relabeled* (config-only) to be the genuine `dev` environment going forward. No iOS app changes required.

## Target end state

| | Logical env | Physical stack | ECR/cluster/service prefix | DynamoDB table | `api_domain` |
|---|---|---|---|---|---|
| **New, fresh** | `prod` | `defend-prod` | `defend-prod-*` | `24defend-domains-prod` | `api.24defend.com` (after cutover) |
| **Existing, frozen** | `dev` | `defend-dev` | `defend-dev-*` (unchanged) | `24defend-domains` (unchanged) | `api-dev.24defend.com` (new, optional) |

Physical and logical names finally match on both sides going forward — no permanent "prod is secretly called defend-dev" footnote needed in `CLAUDE.md`.

## Plan

### 1. `infra/config.py` — redesign `ENVIRONMENTS`

```python
ENVIRONMENTS = {
    "dev": {                                # the existing stack, relabeled — nothing physical changes
        "stack_name": "defend-dev",         # frozen — matches the existing CFN stack, DO NOT CHANGE
        "resource_prefix": "defend-dev",    # frozen — ECR/cluster/service/task-role/secrets naming
        "bucket_env": "dev",                # frozen — S3 bucket suffix (24defend-www-dev, etc.)
        "dynamodb_table_name": "24defend-domains",  # frozen — existing test data, kept as-is
        "account": "081856108753",
        "region": "us-east-1",
        "fargate_cpu": 512,
        "fargate_memory": 1024,
        "desired_count": 1,
        "bedrock_model_id": "zai.glm-4.7",  # was stale "us.anthropic.claude-sonnet-4-6" — match actual runtime
        "api_domain": "api-dev.24defend.com",  # new CNAME, additive — no longer owns api.24defend.com
        "deploy_website": False,            # marketing site doesn't need a dev clone
        "deploy_dashboard": True,           # dashboard needs a non-prod target to test against
    },
    "prod": {                               # brand-new, clean stack
        "stack_name": "defend-prod",
        "resource_prefix": "defend-prod",
        "bucket_env": "prod",
        "dynamodb_table_name": "24defend-domains-prod",  # new table — "24defend-domains" stays taken by dev until a later cleanup
        "account": "081856108753",
        "region": "us-east-1",
        "fargate_cpu": 512,
        "fargate_memory": 1024,
        "desired_count": 1,                 # bump later as a separate capacity decision
        "bedrock_model_id": "zai.glm-4.7",
        "api_domain": "api.24defend.com",   # the domain the app already has hardcoded
        "deploy_website": True,
        "deploy_dashboard": True,
    },
}
```

### 2. `infra/stack.py` — use the new fields instead of `env_name`

- Replace `prefix = f"defend-{env_name}"` → `prefix = env_config["resource_prefix"]`.
- `is_prod = env_name == "prod"` stays as-is.
- DynamoDB `table_name="24defend-domains"` (hardcoded) → `table_name=env_config["dynamodb_table_name"]`.
- Bucket names (`bloom_bucket`, `www_bucket`, `dashboard_bucket`) → replace the raw `{env_name}` interpolation with `{env_config['bucket_env']}`.
- Wrap the `www_bucket`/`www_distribution` block in `if env_config.get("deploy_website", True):` and the `dashboard_bucket`/`dashboard_distribution` block in `if env_config.get("deploy_dashboard", True):`. Guard the corresponding `CfnOutput`s.
- Everything else (ECR repo, secrets, cluster, task role, ACM cert, Fargate service, ALB) already uses `prefix`/`env_config["api_domain"]` — no change needed beyond the `prefix` source above.

### 3. `infra/app.py` — stack construct id from config, not `env_name`

- `DefendStack(app, f"defend-{env_name}", ...)` → `DefendStack(app, env_config["stack_name"], ...)`. For `dev` this keeps pointing at the *existing* CloudFormation stack (`defend-dev`); for `prod` this creates a brand-new stack (`defend-prod`).

### 4. Operational skills — stop hardcoding resource names

Same pattern repeats across `.claude/skills/deploy-backend-fast.md`, `deploy.md`, `deploy-www.md`, `clear-cached-verdict.md`, `status.md`, `logs-backend.md`, `add-domain.md`, `ingest-now.md`, `onboard-new-dev.md`.

Fix: introduce one small shared mapping at the top of each script:

```bash
ENV="${1:-dev}"
case "$ENV" in
  prod) PREFIX="defend-prod"; API_DOMAIN="api.24defend.com" ;;
  dev)  PREFIX="defend-dev";  API_DOMAIN="api-dev.24defend.com" ;;
esac
```

...then use `$PREFIX` and `$API_DOMAIN` everywhere those scripts currently hardcode `defend-dev`/`api.24defend.com`. Representative edits:
- `deploy-backend-fast.md`: `ECR_REPO`, `--cluster`, `--service`, health-check curl.
- `deploy.md`: secrets `--secret-id`, cluster/service names, DNS table (add both the `api` and `api-dev` CNAME rows once cutover happens), "nuclear option" stack name/bucket.
- `deploy-www.md` / `clear-cached-verdict.md` / `status.md` / `logs-backend.md` / `add-domain.md` / `ingest-now.md` / `onboard-new-dev.md`: same substitution wherever they reference physical names.

### 5. `CLAUDE.md` — document the (now-aligned) naming

Add a short note under "Deployment patterns": as of the cutover date, `defend-prod` is production (`api.24defend.com`) and `defend-dev` is the dev/test sandbox (`api-dev.24defend.com`) — physical names finally match logical roles. Mention that `defend-dev`'s DynamoDB table (`24defend-domains`) predates the split and holds pre-cutover test data, not production data (production data lives in `24defend-domains-prod`).

### 6. Frontend — env-aware API base URL

- `frontend/.env.development` → `VITE_API_BASE_URL=/api` (uses the Vite proxy).
- `frontend/.env.production` → `VITE_API_BASE_URL=https://api.24defend.com`.
- `frontend/.env.staging` (new Vite mode, `vite build --mode staging`) → `VITE_API_BASE_URL=https://api-dev.24defend.com`.
- `frontend/vite.config.ts`: proxy `target` reads from `process.env.VITE_DEV_PROXY_TARGET ?? 'https://api-dev.24defend.com'`, so local `npm run dev` stops silently hitting real production data by default.

### 7. iOS — no code changes required

`ios/Shared/APIClient.swift:19` (`https://api.24defend.com`) stays untouched. The whole point of doing this as a DNS-level cutover behind the same hostname is that the already-installed TestFlight build keeps working transparently once the CNAME flips — no new build, no App Store Connect upload, no tester action needed for this migration specifically.

### 8. Execution sequence (once code changes are approved and merged)

Risk-sensitive part — sequence matters. Unlike v1, the risky action here is a **DNS cutover** (step 6), not an in-place stack update.

1. `cdk deploy` with `DEFEND_ENV=prod` to create the brand-new `defend-prod` stack. Purely additive — zero risk to the existing `defend-dev` stack, since it's a different stack, different ECR repo, different table, different ALB.
2. Populate `defend-prod/api-key` and `defend-prod/serper-api-key` in Secrets Manager (same pattern as `/deploy`'s existing secrets step).
3. Wait for the `defend-prod` ACM certificate to validate (add the DNS validation CNAME in GoDaddy — additive, doesn't touch the live `api` record) and for the ECS service to reach steady state.
4. Run the ingestion pipeline (`/ingest-now`-style) against `defend-prod`'s new table (`24defend-domains-prod`) so it has real blacklist/whitelist data before any real traffic hits it — don't cut over to an empty table.
5. Smoke-test `defend-prod` directly via its ALB DNS name (or a temporary `curl --resolve api.24defend.com:443:<new-alb-ip>`) to confirm `/health` and `/check` work end-to-end against known-good and known-bad domains, without touching the live `api.24defend.com` CNAME yet.
6. **Cutover**: lower the `api.24defend.com` CNAME's TTL a few minutes ahead of time, then repoint it from the old (`defend-dev`) ALB to the new (`defend-prod`) ALB in GoDaddy. This is the one step with any user-facing risk — a short heads-up to internal TestFlight testers beforehand is worth it.
7. `curl https://api.24defend.com/health` repeatedly during the propagation window; confirm real traffic starts landing in `defend-prod`'s CloudWatch logs.
8. Add a new GoDaddy CNAME `api-dev` → the `defend-dev` ALB (additive, doesn't touch anything above) so `dev` has its own stable domain per the config in step 1.
9. `curl https://api-dev.24defend.com/health` to confirm the dev environment is reachable at its new address.
10. Build/deploy the dashboard once for prod (`vite build --mode production`) and once for dev (`vite build --mode staging`) to their respective CloudFront distributions.
11. After a burn-in period (24–48h) confirming `defend-prod` is stable, treat `defend-dev`'s pre-cutover DynamoDB data as test-only; no destructive cleanup required immediately, but it's no longer "the real data" — that distinction now belongs to `24defend-domains-prod`.

## Verification

- `cd backend && .venv/bin/python -m pytest tests/ -v` — sanity check nothing in `backend/app/config.py` defaults broke.
- `cdk synth` for both `DEFEND_ENV=dev` and `DEFEND_ENV=prod` locally (no deploy) to confirm both synthesize without error before touching AWS.
- `cdk diff` with `DEFEND_ENV=dev` against the *existing* `defend-dev` stack — this is the safety gate that replaces v1's prod-side check. **Verify it shows no `Replace`/`Delete+Create`** for `DomainsTable`, `EcrRepo`, `Cluster`, `Service`, secrets, or buckets — only the `api_domain` change (which only affects a *new* ACM cert/output, since the old cert stays until the domain is actually removed from that stack's cert... double check `cdk diff` doesn't try to delete the existing `ApiCert` in a way that would drop HTTPS on `defend-dev` before the new `api-dev` cert is ready) and additive changes.
- `defend-prod`'s `cdk deploy` in step 1 needs no diff gate — it's a plain new-stack creation.
- After execution: confirm `dashboard.24defend.com` (prod) and the new dev dashboard URL both load and correctly hit their respective API domains (check Network tab for the right `Origin`/CORS).
- Confirm the TestFlight app (unchanged binary) continues working end-to-end after the cutover, proving the DNS-only approach worked without needing a new build.

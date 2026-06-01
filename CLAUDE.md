# 24Defend - Claude Code Instructions

## Project structure

```
ios/           -- iOS app (SwiftUI + NetworkExtension)
backend/       -- Python FastAPI (DynamoDB + Bedrock)
ml/            -- ML training pipeline
infra/         -- AWS CDK
www/           -- Website (S3 + CloudFront)
research/      -- Analysis documents
```

## Key URLs

- API: https://api.24defend.com
- Website: https://www.24defend.com
- GitHub: github-24defend:andresgurmendez/24defend

## Legal entity

The project is operated by **TONLER S.A.S.** (Uruguay), not by an individual. Always use this name on App Store / Play Store metadata, legal copy, contracts, and external-facing materials. Detailed registry data lives in `CHANGELOG.md` under "Legal entity".

| Field | Value |
|-------|-------|
| Legal name | TONLER S.A.S. |
| D-U-N-S | 81-335-4968 |
| RUT | 220621480018 |
| Address | Miguel Barreiro 3236, Apt. 602, Montevideo 11300, Uruguay |
| Corporate email | maximo@24defend.com (private, used for Apple/D&B/contracts) |
| Public email | dev@24defend.com (website, app contact) |

Apple Developer Team ID `332CN243S9` is undergoing migration Individual → Organization (case #102901828798).

## Patterns we follow

### iOS project regeneration
After adding/removing Swift files, run `cd ios && xcodegen generate`, then restore Info.plist (CFBundleDisplayName for app, NSExtension for tunnel). xcodegen overwrites plists. Always restore CFBundleDisplayName in app plist and NSExtension dict in tunnel plist after regeneration.

### Infrastructure allowlist
Known CDN/platform domains skip all detection (`DomainChecker.isInfrastructureDomain`). Add domains here rather than modifying bloom filter logic. Lives in `ios/Shared/DomainChecker.swift`. Includes `cloudflare.net` (CNAME-chain target), `jsdelivr.net`, ad-tech (`adnxs.com`, `ltmsphrcl.net`, `adzonestatic.com`, `demdex.net`, `omtrdc.net`, etc.). The check runs on the BASE domain after `extractBaseDomain()`, so any subdomain of a listed CDN is automatically allowed.

### Bloom filter false positives
Never block on bloom filter alone. On a bloom hit: check local FP list first (instant), then confirm with backend API (DynamoDB lookup, ~50ms). FPs are distributed via GET /daily-false-positives endpoint (public, no auth, polled every 30 min).

### ML classifier is silent
Never show user-facing warnings from ML model. Submit suspicious domains to API in background. Only brand rule engine warnings are user-facing.

### Signed modulo
Swift bloom filter uses Python-style signed int32 modulo (pythonMod function). Never use unsigned modulo for bloom filter lookups.

### Shared infrastructure filtering
At ingestion time, the backend downloads the Majestic Million top 100K popular domains and filters out any blacklist domain whose base domain appears in that list. Located in `backend/app/ingestion/runner.py`. The hardcoded `SHARED_INFRASTRUCTURE_DOMAINS` set (43 domains) is a fallback if the download fails.

### Smart notification suppression
Only notify for domains containing a brand keyword. Generic blacklist blocks are silenced. Page resource window: suppress within 3s of a whitelist hit. Rate limit: max 1 per 5s. Principle: "silence is the default state." DNS blocking and telemetry are unaffected.

### Pending investigations (retroactive warnings) — agent-controlled
When the ML classifier silently submits a domain, it's added to PendingInvestigation. A 30-second polling timer checks the API for results. The decision to send a retroactive notification is **owned by the agent** — `/check` returns `should_notify: bool` in its response, and the iOS app respects that field (`ios/Shared/PendingInvestigation.swift`). Blacklist hits always set `should_notify=true`; agent verdicts set it true only when confident (>=0.85) AND the domain impersonates a specific brand AND multiple strong signals converge (see `backend/app/investigation/graph.py` system prompt). When `should_notify=true`: forced notification "Sitio peligroso confirmado — cambia tu contrasena" + add to runtime blacklist. Max 20 pending, expire after 10 minutes.

### Agent prompt — ad-tech / CDN awareness
Backend agent system prompt explicitly explains: CNAME chains like `*.cdn.cloudflare.net` are legitimate CDN endpoints (not impersonation); obfuscated ad-tech names (`ltmsphrcl.net` = Lotame, `adnxs.com` = Xandr) are normal in ad tech; Safe Browsing flags on ad domains are common FPs. Modify the prompt in `backend/app/investigation/graph.py` if new categories of legitimate-but-suspicious-looking domains appear.

### Safe Browsing tool — uses Lookup API v4
The `safe_browsing_check` tool was previously hitting Google Transparency Report web API, which returns CAPTCHA 302 redirects to server IPs — the tool reported "MAY be flagged" for EVERY domain, causing widespread agent FPs. Now uses the proper Lookup API v4 (requires `DEFEND_SAFE_BROWSING_API_KEY`). Without the key, the tool explicitly tells the agent "do NOT treat as a flag" — never silently assume a hit.

### Reward / loyalty scam vocabulary
Phishing vocabulary includes reward/loyalty terms (`puntos`, `premio`, `ganaste`, `sorteo`, `regalo`, `beneficio`, `promocion`, `oferta`, `descuento`, `cupon`, `recompensa`, `canje`, `redimir`). High-risk TLDs include `.st`, `.su`, `.ga`, `.ws`, `.to`, `.me`. The trigger pattern was `oca.puntos.st` (real fraud impersonating OCA loyalty program). Lives in `ios/Shared/BrandRuleEngine.swift`, `ml/features.py`, and the backend heuristics tool.

### Privacy
Never record allowed/normal domains. Only blocked/warned domains in telemetry. Anonymous device UUID, not Apple ID.

## Deployment patterns

### Backend — fast iteration (preferred during dev)
**CI is broken** (missing `AWS_DEPLOY_ROLE_ARN` GitHub secret). The fast path is to build, push to ECR, and force ECS redeploy directly. See `/deploy-backend-fast` skill. Bump the `# Force rebuild: <date>` comment in `backend/Dockerfile` if Docker caches too aggressively. Always use `--platform linux/amd64` for the build (Macs are ARM, Fargate is AMD64).

### Backend — full CDK deploy
Use the `/deploy` skill only when infrastructure changes (new IAM role, new env var, new service). It's slower and more careful. For code-only changes use `/deploy-backend-fast`.

### Website — S3 + CloudFront
The site lives in `www/` and is served from `s3://24defend-www-dev/` via CloudFront distribution `E2NV1T0DZ96AY`. Use the `/deploy-www` skill — it runs `aws s3 sync` + creates a CloudFront invalidation. No CDK needed for content-only edits.

### Bad agent verdicts — clear DynamoDB cache
When the agent caches an incorrect verdict (e.g., classifies a CDN domain as fraud), delete the entry from the `24defend-domains` table to force re-investigation on next `/check`. Use the `/clear-cached-verdict` skill.

## Testing

160+ backend tests. Run with:
```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```
iOS tests require Xcode.

## Git

Use github-24defend SSH host alias (separate key from other repos). Push with `ssh-add ~/.ssh/id_24defend` first.

## Secrets

Secrets Manager values must be set manually after first stack creation. API key is "dev-api-key-24defend". AWS credentials for the dev account (081856108753) are in `aws.sh` at repo root — these are IAM user keys for the bedrock24defend user.

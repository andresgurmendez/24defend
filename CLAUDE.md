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
After adding/removing Swift files, run `cd ios && xcodegen generate` to update the xcodeproj. Custom Info.plist keys required for App Store validation (CFBundleDisplayName, UILaunchScreen, UISupportedInterfaceOrientations, ITSAppUsesNonExemptEncryption, NSExtension) are declared in `project.yml` under each target's `info.properties`, so xcodegen preserves them automatically — no manual restoration needed.

Privacy Manifests (`PrivacyInfo.xcprivacy`) for both targets live inside their source folders and are picked up as resources by xcodegen's folder scan. When adding a new required-reason API call or a new data-collection category, update BOTH `.xcprivacy` files AND the App Privacy questionnaire in App Store Connect (they must agree).

### Infrastructure allowlist
Known CDN/platform domains skip all detection (`DomainChecker.isInfrastructureDomain`). Add domains here rather than modifying bloom filter logic. Lives in `ios/Shared/DomainChecker.swift`. Includes `cloudflare.net` (CNAME-chain target), `jsdelivr.net`, ad-tech (`adnxs.com`, `ltmsphrcl.net`, `adzonestatic.com`, `demdex.net`, `omtrdc.net`, etc.). The check runs on the BASE domain after `extractBaseDomain()`, so any subdomain of a listed CDN is automatically allowed.

### Bloom filter false positives
Never block on bloom filter alone. On a bloom hit: check local FP list first (instant), then confirm with backend API (DynamoDB lookup, ~50ms). FPs are distributed via GET /daily-false-positives endpoint (public, no auth, polled every 30 min).

### ML classifier is silent
Never show user-facing warnings from ML model — it has a high FP rate (observed: 100% "phishing probability" on Salesforce/DataXu HDFS subdomains). Submit suspicious domains to API in background. Only brand rule engine warnings are user-facing.

**Gap to be aware of:** if a real phishing domain misses the brand-rule threshold (`isHighRisk`, score >= 0.7) but is caught by ML, the user gets no yellow at browse time and only a RED retroactive notification after the agent confirms. The right response is to tighten brand-rule signals (add missing brand keywords, TLDs, or phishing vocabulary) so the domain crosses the brand-rule threshold — not to loosen ML gating. See `ios/Shared/BrandRuleEngine.swift` for the scoring function.

### Signed modulo
Swift bloom filter uses Python-style signed int32 modulo (pythonMod function). Never use unsigned modulo for bloom filter lookups.

### Shared infrastructure filtering
At ingestion time, the backend downloads the Majestic Million top 100K popular domains and filters out any blacklist domain whose base domain appears in that list. Located in `backend/app/ingestion/runner.py`. The hardcoded `SHARED_INFRASTRUCTURE_DOMAINS` set (43 domains) is a fallback if the download fails.

### Smart notification suppression
Only notify for domains containing a brand keyword. Generic blacklist blocks are silenced. Page resource window: suppress within 3s of a whitelist hit. Rate limit: max 1 per 5s (skipped for forced red escalations). **Session dedup by BASE DOMAIN**: one yellow + one red per eTLD+1 per session (`sorteo.brou.hk` and `www.sorteo.brou.hk` share `brou.hk` so the user gets 1 yellow + 1 red, not 4). Red escalation is still allowed once even after yellow already fired. State: `yellowNotified`/`redNotified` sets in `PacketTunnelProvider`. Principle: "silence is the default state." DNS blocking and telemetry are unaffected.

### Pending investigations (retroactive warnings) — agent-controlled
When the ML classifier silently submits a domain OR the brand rule engine fires a yellow warning, the domain is added to `PendingInvestigation` and a fire-and-forget backend `/check` is spawned. DNS is forwarded immediately — the user is NEVER stalled waiting for the agent. A 30-second polling timer checks the API for results. The decision to send a retroactive notification is **owned by the agent** — `/check` returns `should_notify: bool`, and iOS respects it (`ios/Shared/PendingInvestigation.swift`). Blacklist hits always `should_notify=true`; agent verdicts set it true only when confident (>=0.85) AND the domain impersonates a specific brand AND multiple strong signals converge (see `backend/app/investigation/graph.py`). When `should_notify=true`: forced red notification "Sitio fraudulento confirmado — Si ingresaste algún dato, cambiálo en el sitio o app oficial de la marca." + add to runtime blacklist so future visits block pre-DNS. Max 20 pending, expire after 10 minutes.

**should_notify DDB persistence**: `put_domain` in `backend/app/domain_service.py` writes the field when True; `_item_to_entry` reads it with False default. Without both, the field silently drops between agent verdict and cache read, and the poll loop never sees `True` → no RED notification even for confirmed phishing.

### Agent prompt — infrastructure awareness
Backend agent system prompt explicitly categorises the "not-phishing" landscape: CDN chains (`*.cdn.cloudflare.net`, `*.akamaiedge.net`), obfuscated ad-tech (`ltmsphrcl.net` = Lotame, `adnxs.com` = Xandr), email-marketing platforms (Salesforce Marketing Cloud, mailgun, mailchimp, zetaglobal, Movable Ink, AWS SES tracking domain `awstrack.me`, substack), deep-linking (branch.io/bnc.lt), cloud hosting (azurewebsites.net, herokuapp.com), registrars (godaddy.com subdomains), and big-brand marketing subdomains (aa.com, hilton.com, washingtonpost.com with prefixes like `l.`, `email.`, hash tokens). Signal weighting is spelled out: "no HTTPS on port 443 alone is not proof of phishing"; "fresh SSL certs on marketing subdomains are normal"; Safe Browsing "potential" hits on infra are usually FPs. Modify the prompt in `backend/app/investigation/graph.py` if new categories of legitimate-but-suspicious-looking domains appear.

### Pre-agent short-circuit (popular-domain allowlist)
`backend/app/popular_domains.py` maintains an in-memory allowlist: Majestic Million top 100K (loaded on startup, refreshed) plus a curated `VENDOR_ALLOWLIST` set (~90 explicit roots covering CDN, cloud hosting, email marketing, ad-tech, deep-linking, registrars, big-brand marketing subdomains). `/check` short-circuits any domain whose eTLD+1 is in the popular set — returns `verdict=allow, source=popular` in <1s without invoking the agent. Blacklist/whitelist hits still take precedence. Adding a new "legit but agent kept blocking it" domain: append to `VENDOR_ALLOWLIST`. The Majestic list only loads at startup; a new deploy is enough to refresh but not required (vendor list works immediately).

### Safe Browsing tool — uses Lookup API v4
The `safe_browsing_check` tool was previously hitting Google Transparency Report web API, which returns CAPTCHA 302 redirects to server IPs — the tool reported "MAY be flagged" for EVERY domain, causing widespread agent FPs. Now uses the proper Lookup API v4 (requires `DEFEND_SAFE_BROWSING_API_KEY`). Without the key, the tool explicitly tells the agent "do NOT treat as a flag" — never silently assume a hit.

### Phishing vocabulary + high-risk TLDs (BrandRuleEngine)
Reward/loyalty terms (`puntos`, `premio`, `ganaste`, `sorteo`, `regalo`, `beneficio`, `promocion`, `oferta`, `descuento`, `cupon`, `recompensa`, `canje`, `redimir`) and refund/tax-scam terms (`devolucion`, `reintegro`, `reembolso`, `reclamo`, `impuesto`, `iva`, `irpf`) count as phishing vocabulary. High-risk TLDs include `.st`, `.su`, `.ga`, `.ws`, `.to`, `.me` and the Asian TLDs commonly used for LatAm phishing (`.hk`, `.cn`, `.in`, `.id` — every observed OCA/BROU FN used `.hk`). Trigger patterns: `oca.puntos.st` (real OCA loyalty fraud), `devolucion.dgi.hk` (real DGI tax-refund scam). Lives in `ios/Shared/BrandRuleEngine.swift`, `ml/features.py`, and the backend heuristics tool. When adding a new phishing-vocabulary word or high-risk TLD, add regression coverage in `ios/Tests/BrandRuleEngineTests.swift`.

### LLM: GLM 4.7 on Bedrock
The investigation agent runs on `zai.glm-4.7` (native Bedrock ID — no `bedrock/` prefix; that's LiteLLM notation). GLM 4.7 produces the `reasoning` field natively in Uruguayan Spanish with brand-specific knowledge (e.g. names BROU's "BancaNet" product correctly). Config in `backend/app/config.py:bedrock_model_id`. Sonnet (`us.anthropic.claude-sonnet-4-6`) is the fallback and can be swapped via `DEFEND_BEDROCK_MODEL_ID` env. Multi-model rotation for rate-limit resilience is tracked in `issues.md`.

### Privacy
Never record allowed/normal domains. Only blocked/warned domains in telemetry. Anonymous device UUID, not Apple ID.

## Deployment patterns

### ⚠️ All infra changes MUST go through CDK
Never modify AWS resources through the console or one-off `aws` CLI
commands (e.g. `aws ecs register-task-definition`,
`aws ecs update-service --task-definition ...`,
`aws ecr set-repository-policy`, `aws iam put-role-policy`, editing
resources in the console, etc.). Anything not in `infra/stack.py` is
drift — the next `cdk deploy` will silently revert it, and future
readers cannot trace where the change came from. If you need something
that CDK doesn't currently do, add it to `infra/stack.py` and
`cdk deploy` — that is the ONLY sanctioned path. Data-plane operations
that CDK doesn't own (e.g. `dynamodb delete-item` for a bad cache
verdict, ECR image pushes, S3 object uploads) are fine — the rule is
about infrastructure resources, not runtime state. When in doubt: if it
would show up in `cdk diff`, it must go through CDK.

### Backend — fast iteration (preferred during dev)
**CI is broken** (missing `AWS_DEPLOY_ROLE_ARN` GitHub secret). The fast path is to build, push to ECR, and force ECS redeploy directly. See `/deploy-backend-fast` skill. Bump the `# Force rebuild: <date>` comment in `backend/Dockerfile` if Docker caches too aggressively. Always use `--platform linux/amd64` for the build (Macs are ARM, Fargate is AMD64).

### Backend — full CDK deploy
Use the `/deploy` skill only when infrastructure changes (new IAM role, new env var, new service). It's slower and more careful. For code-only changes use `/deploy-backend-fast`.

### Website — S3 + CloudFront
The site lives in `www/` and is served from `s3://24defend-www-dev/` via CloudFront distribution `E2NV1T0DZ96AY`. Use the `/deploy-www` skill — it runs `aws s3 sync` + creates a CloudFront invalidation. No CDK needed for content-only edits.

### Bad agent verdicts — clear DynamoDB cache
When the agent caches an incorrect verdict (e.g., classifies a CDN domain as fraud), delete the entry from the `24defend-domains` table to force re-investigation on next `/check`. Use the `/clear-cached-verdict` skill.

## Testing

200+ backend tests including regression coverage for known FPs and known phishing (see `tests/test_popular_domains.py::TestKnownFPsFromProdCache`). Run with:
```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```
iOS tests (`ios/Tests/*.swift`) require Xcode target membership to actually execute — new files may need adding to the Tests target in Xcode before they run.

## Git

Use github-24defend SSH host alias (separate key from other repos). Push with `ssh-add ~/.ssh/id_24defend` first.

## Secrets

Secrets Manager values must be set manually after first stack creation. API key is "dev-api-key-24defend". AWS credentials for the dev account (081856108753) are in `aws.sh` at repo root — these are IAM user keys for the bedrock24defend user.

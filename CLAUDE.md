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

## Patterns we follow

### iOS project regeneration
After adding/removing Swift files, run `cd ios && xcodegen generate`, then restore Info.plist (CFBundleDisplayName for app, NSExtension for tunnel). xcodegen overwrites plists. Always restore CFBundleDisplayName in app plist and NSExtension dict in tunnel plist after regeneration.

### Infrastructure allowlist
Known CDN/platform domains skip all detection (DomainChecker.isInfrastructureDomain). Add domains here rather than modifying bloom filter logic.

### Bloom filter false positives
Never block on bloom filter alone. On a bloom hit: check local FP list first (instant), then confirm with backend API (DynamoDB lookup, ~50ms). FPs are distributed via GET /daily-false-positives endpoint (public, no auth, polled every 30 min).

### ML classifier is silent
Never show user-facing warnings from ML model. Submit suspicious domains to API in background. Only brand rule engine warnings are user-facing.

### Backend deploy
Force rebuild by changing Dockerfile comment. CDK caches Docker image by content hash.

### Signed modulo
Swift bloom filter uses Python-style signed int32 modulo (pythonMod function). Never use unsigned modulo for bloom filter lookups.

### Shared infrastructure filtering
43 shared-infrastructure domains (ad networks, CDNs, analytics, social platforms) are filtered at ingestion in `backend/app/ingestion/runner.py` (`SHARED_INFRASTRUCTURE_DOMAINS` set). These host both legitimate and malicious content -- blocking at DNS level breaks pages. Add domains here when threat feeds include shared-infrastructure domains.

### Smart notification suppression
Only notify for domains containing a brand keyword. Generic blacklist blocks are silenced. Page resource window: suppress within 3s of a whitelist hit. Rate limit: max 1 per 5s. Principle: "silence is the default state." DNS blocking and telemetry are unaffected.

### Privacy
Never record allowed/normal domains. Only blocked/warned domains in telemetry. Anonymous device UUID, not Apple ID.

## Testing

160+ backend tests. Run with:
```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```
iOS tests require Xcode.

## Git

Use github-24defend SSH host alias (separate key from other repos). Push with `ssh-add ~/.ssh/id_24defend` first.

## CDK deploy

Source aws.sh first. Set `JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1`. Always `rm -rf cdk.out` before deploy.

## Secrets

Secrets Manager values must be set manually after first stack creation. API key is "dev-api-key-24defend".

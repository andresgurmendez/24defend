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
Never block on bloom filter alone. Always confirm with API. FPs are distributed via /daily-false-positives endpoint.

### ML classifier is silent
Never show user-facing warnings from ML model. Submit suspicious domains to API in background. Only brand rule engine warnings are user-facing.

### Backend deploy
Force rebuild by changing Dockerfile comment. CDK caches Docker image by content hash.

### Signed modulo
Swift bloom filter uses Python-style signed int32 modulo (pythonMod function). Never use unsigned modulo for bloom filter lookups.

### Privacy
Never record allowed/normal domains. Only blocked/warned domains in telemetry. Anonymous device UUID, not Apple ID.

## Testing

155+ backend tests. Run with:
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

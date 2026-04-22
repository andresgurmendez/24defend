# 24Defend — Development Summary

Built April 12-21, 2026. 38 commits, from zero to production-deployed MVP.

---

## April 7, 2026 -- Majestic Million ingestion filtering

### Majestic Million shared infrastructure filtering
- Ingestion now downloads the Majestic Million top 100K popular domains (~15MB CSV) and filters out any blacklist domain whose base domain appears in that list
- Replaces the hardcoded 43-domain `SHARED_INFRASTRUCTURE_DOMAINS` set as the primary filter
- Automatic -- no manual curation needed; covers adnxs.com (#2215), doubleclick.net (#25K), googletagmanager.com (#36K), and thousands more
- Hardcoded set remains as a fallback if the Majestic Million download fails
- Located in `backend/app/ingestion/runner.py`

---

## April 7, 2026 -- Bloom filter API confirmation, notification suppression, ingestion filtering

### Bloom filter API confirmation
- Bloom filter hit no longer blocks instantly
- Checks local false positive list first (instant)
- If not in FP list, confirms with backend API (DynamoDB lookup, ~50ms)
- If API says block: actually block + add to runtime blacklist
- If API says allow: forward DNS + record as false positive
- Eliminates all bloom filter false positives

### False positive distribution
- New endpoint: GET /daily-false-positives (public, no auth)
- Returns domains with verdict=allow checked in last 48h
- Device polls every 30 min alongside daily blacklist
- Prevents repeated API calls for known FPs

### Shared infrastructure filtering at ingestion
- 43 shared-infrastructure domains filtered from threat feeds at ingestion time
- Categories: ad networks, CDNs, analytics, social platforms, major services, payment providers
- These domains host both legitimate and malicious content -- blocking at DNS level breaks pages
- Located in `SHARED_INFRASTRUCTURE_DOMAINS` set in `backend/app/ingestion/runner.py`

### Smart notification suppression
- Only notify for domains containing a brand keyword (brou, itau, santander, etc.)
- Generic blacklist blocks (ad trackers, CDN malware, background app requests) silenced
- Page resource window: suppress notifications within 3s of a whitelist hit
- Rate limit: max 1 notification per 5 seconds
- DNS blocking and telemetry recording unaffected -- only the notification is filtered
- Principle: "silence is the default state"

### Updated pipeline (9 layers: 0-8)
0. DNS verdict cache
1. Runtime blacklist
2. Infrastructure allowlist
3. Bloom whitelist -> allow
4. Dual bloom blacklist -> check local FP list -> if not FP -> confirm with API -> block or allow
4b. Daily blacklist -> block
5. BK-tree Levenshtein -> warn + API
6. Brand rule engine -> warn + API
7. ML classifier -> silent: submit to API in background
8. Allow

### Other
- 160 backend tests (was 155)
- Key production insight: visiting yahoo.com triggered 10+ notifications for invisible ad tracker domains. Fix: filter at ingestion + suppress notifications for non-brand domains.

---

## What we built

**24Defend** is an anti-phishing app for iOS that blocks fraudulent links in real time. When someone clicks a malicious link — whether it arrives via WhatsApp, SMS, email, or any app — 24Defend blocks it before the page loads.

### iOS App
- Native SwiftUI app with NetworkExtension packet tunnel for DNS-level filtering
- Works across all apps (WhatsApp, SMS, email, Safari, any browser)
- On-device detection: no browsing data leaves the device for 99.8% of queries
- Push notifications for blocked/suspicious domains
- Block detail screen when tapping notifications
- App icon: shield + lock + "24" design

### Backend (Python + AWS)
- FastAPI async backend deployed on AWS Fargate
- DynamoDB for domain storage (whitelist, blacklist, cache)
- LangGraph agent powered by AWS Bedrock Claude Sonnet for AI-driven domain investigation
- 6 investigation tools: DNS/RDAP lookup, SSL certificate check, Levenshtein similarity, Google Search (Serper), Google Safe Browsing, domain heuristics
- Public threat feed ingestion: PhishTank, URLhaus, OpenPhish, Phishing.Army (72,481 blacklisted domains)
- Certificate Transparency log discovery for whitelist auto-building (299 institution subdomains)
- APScheduler: daily ingestion + bloom filter regeneration at 03:00 UTC
- Anonymous telemetry collection from devices

### ML Pipeline
- Synthetic data generator: 7 attack patterns, 17,500 domains
- 20 domain string features (brand keywords, phishing vocabulary, TLD risk, homoglyphs, etc.)
- Logistic regression classifier: AUC 0.998, 1 KB model weights
- Shipped on-device via CDN (weights downloadable, no app update needed)
- Now operates as silent screener: flags suspicious domains for backend investigation without bothering the user

### Infrastructure (CDK)
- VPC with 2-AZ, public + private subnets
- ECS Fargate behind ALB with HTTPS (ACM certificate for api.24defend.com)
- DynamoDB (pay-per-request)
- S3 + CloudFront for bloom filter delivery and website hosting
- Secrets Manager for API keys
- IAM roles for Bedrock + DynamoDB + S3 access
- GitHub Actions CI/CD pipeline
- Multi-account config (dev/prod)

### Website
- Landing page at www.24defend.com (S3 + CloudFront)
- Privacy policy in English and Spanish
- Apple App Store compliant (no fake stats, accurate technical claims)

---

## Detection pipeline (10 layers)

When the user visits any website, the DNS query goes through these layers in order:

| Layer | What | Speed | Action |
|-------|------|-------|--------|
| 0 | DNS verdict cache (LRU, 2K entries, 1hr TTL) | <0.01ms | Cached allow/block |
| 1 | Runtime blacklist (domains confirmed by backend this session) | O(1) | Block |
| 2 | Infrastructure allowlist (Google, Apple, CDNs, etc.) | O(n) | Allow |
| 3 | Bloom filter whitelist (39 institution base domains) | O(k) | Allow |
| 4 | Dual bloom filter blacklist (72K domains, both must match) | O(2k) | Check local FP list, then confirm with API |
| 4b | Daily blacklist (polled every 30 min from backend) | O(n) | Block |
| 5 | BK-tree Levenshtein (fuzzy match to whitelist) | O(log n) | Warn + check API |
| 6 | Brand rule engine (25 UY brands + 40 phishing words) | O(1) | Warn + check API |
| 7 | ML classifier (20 features, logistic regression) | <1ms | Silent: submit to API |
| 8 | Allow | — | Forward DNS |

**Result**: 98.2% of queries served from cache. 0.2% hit the backend API. Zero false positive warnings to the user.

---

## Key numbers

| Metric | Value |
|--------|-------|
| Blacklisted domains | 72,481 base domains |
| Whitelisted institutions | 24 (Uruguay) |
| Whitelisted subdomains | 299 (auto-discovered via CT logs) |
| Bloom filter size | 127 KB (blacklist A) + ~100 KB (blacklist B) |
| Bloom filter FP rate | ~1 in 670,000 (dual filter) |
| ML model AUC | 0.998 |
| ML model size | 1 KB |
| Cache hit rate | 98.2% |
| API call rate | 0.2% of queries |
| Backend latency (cache hit) | ~50ms |
| Backend latency (agent investigation) | 15-30s |
| Bedrock cost per investigation | ~$0.005 |
| Estimated cost at 100 users | ~$0.80/day |
| Backend unit tests | 160 |
| iOS unit tests | ~25 (MurmurHash3 cross-validation, bloom filter, DNS cache, classifier) |

---

## Uruguay-specific data

- 24 financial institutions whitelisted (BROU, Itau, Santander, Scotiabank, BBVA, HSBC, OCA, Prex, MercadoPago, MercadoLibre, Abitab, RedPagos, Antel, Movistar, Claro, PedidosYa, GUB, BPS, DGI, BCU, AGESIC, and more)
- 25 brand keywords for brand impersonation detection
- 40+ Spanish phishing vocabulary words
- Research document with 7 documented attack patterns from WeLiveSecurity, CERTuy, BioCatch, Axur

---

## Bugs found and fixed in production

1. **ARM vs AMD64**: Docker image built for Mac ARM, Fargate runs AMD64 → `exec format error`
2. **DynamoDB ListTables**: container tried to create table on startup, no IAM permission
3. **Bloom filter signed modulo**: Python mmh3 returns signed int32, Swift used unsigned → different bit positions → bloom filter lookups failed
4. **ML classifier false positives**: flagged CDN domains (googleapis.com, akamaiedge.net) as phishing due to high digit count + deep subdomains
5. **Bloom filter false positives**: single bloom filter with 72K entries had 0.1% FP rate → blocked legitimate domains
6. **Blacklist ingestion**: 28K per-domain DynamoDB lookups took minutes, causing startup timeout
7. **Bloom filter API key**: iOS used wrong API key for bloom filter download (dev vs production)
8. **Infrastructure domains**: bloom filter check ran before infrastructure allowlist

---

## Files and structure

```
24defend-mono/
├── ios/                          # iOS app (SwiftUI + NetworkExtension)
│   ├── TwentyFourDefend/         # Main app target
│   ├── TwentyFourDefendPacketTunnel/  # Packet tunnel extension
│   ├── Shared/                   # Shared code (13 Swift files)
│   └── Tests/                    # iOS unit tests
├── backend/                      # Python FastAPI backend
│   ├── app/                      # Application code
│   │   ├── routes/               # API endpoints (check, admin, telemetry)
│   │   ├── investigation/        # LangGraph agent + tools
│   │   └── ingestion/            # Threat feed ingestion
│   └── tests/                    # 155 unit tests
├── ml/                           # ML pipeline
│   ├── features.py               # Feature extraction (20 features)
│   ├── generate_synthetic.py     # Synthetic data generator
│   ├── train.py                  # Model training
│   └── models/                   # Exported model weights
├── infra/                        # AWS CDK infrastructure
│   ├── stack.py                  # Single stack (VPC, Fargate, DynamoDB, etc.)
│   └── config.py                 # Dev/prod environment config
├── www/                          # Website (landing + privacy policy)
├── research/                     # Analysis documents
│   ├── uy-latam-phishing-patterns.md
│   ├── pipeline-efficiency-analysis.md
│   └── improvements.md
├── architecture.md               # Full system architecture
├── DISTRIBUTION.md               # Apple Developer account guide
└── .github/workflows/deploy.yml  # CI/CD
```

---

## What's next

1. **TestFlight upload** — app is ready, privacy policy is live, App Store Connect setup needed
2. **Privacy policy review** — Apple compliance verified, ready for submission
3. **Bank demos** — use TestFlight build to demo to UY financial institutions
4. **Active learning** — 1% sampling of unknown domains for model retraining
5. **Share button** — viral growth loop on block notifications
6. **Android** — same architecture, Flutter or native

---

## Accounts and credentials

| Service | Account | Notes |
|---------|---------|-------|
| Apple Developer | Maximo Gurmendez (Individual) | 24Defend Apple ID, $99/year |
| AWS (dev) | 081856108753 | IAM user keys in aws.sh |
| GitHub | andresgurmendez/24defend | SSH key: ~/.ssh/id_24defend |
| GoDaddy | 24defend.com | DNS: api CNAME → ALB, www CNAME → CloudFront |
| Serper | dev@24defend.com | API key in serper.conf |
| Domain | 24defend.com | Registered via GoDaddy |

---

## How to run locally

```bash
# Backend
cd backend && docker compose up --build

# iOS
cd ios && xcodegen generate
open TwentyFourDefend.xcodeproj
# Set signing team + capabilities, Cmd+R

# Tests
cd backend && .venv/bin/python -m pytest tests/ -v

# Deploy
source aws.sh && cd infra && DEFEND_ENV=dev cdk deploy --all
```

# 24Defend Architecture

Anti-phishing link protection for mobile devices, targeting Latin America.

24Defend intercepts DNS queries on iOS devices using a NetworkExtension packet tunnel, checks domains against a 9-layer on-device pipeline (DNS verdict cache, runtime blacklist, infrastructure allowlist, bloom whitelist, dual bloom blacklist with local FP list + API confirmation, daily blacklist, BK-tree fuzzy matching, brand rule engine, silent ML screener), and escalates uncertain domains to a backend investigation agent powered by AWS Bedrock Claude Sonnet. The system ingests public threat feeds daily (filtering shared-infrastructure domains via Majestic Million top 100K at ingestion), generates compact bloom filters that the iOS app downloads for offline protection, and maintains an ML pipeline for training lightweight phishing classifiers from synthetic and real-world data.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [iOS App](#ios-app)
3. [Backend API](#backend-api)
4. [ML Pipeline](#ml-pipeline)
5. [Data Flow: Phishing Link Clicked](#data-flow-phishing-link-clicked)
6. [Infrastructure](#infrastructure)
7. [Configuration](#configuration)
8. [Security Model](#security-model)
9. [Testing](#testing)

---

## System Architecture

```
+----------------------------------------------+
|                  iOS Device                   |
|                                               |
|  +------------------+   +------------------+  |
|  | 24Defend App     |   | Packet Tunnel    |  |
|  | (SwiftUI)        |   | Extension        |  |
|  |                  |   |                  |  |
|  | - Dashboard      |   | - DNS intercept  |  |
|  | - Block log      |   | - 10+ layer check  |  |
|  | - VPN toggle     |   | - Block page     |  |
|  | - Notifications  |   |   HTTP server    |  |
|  +--------+---------+   +-------+----------+  |
|           |                     |              |
|           |  App Group shared   |              |
|           |  (UserDefaults)     |              |
|           +----------+----------+              |
|                      |                         |
+----------------------|-------------------------+
                       |
                       | HTTPS (only for
                       | uncertain domains)
                       |
          +------------v--------------+
          |     Backend API           |
          |     (FastAPI / Python)    |
          |                           |
          |  POST /check              |
          |  GET  /admin/bloom-filter |
          |  POST /admin/domains      |
          |  POST /admin/ingest/*     |
          +-----+----------+----+----+
                |          |    |
       +--------v--+  +---v-+  +--v-----------+
       | DynamoDB   |  | S3  |  | AWS Bedrock  |
       | (domains,  |  |     |  | Claude       |
       |  verdicts, |  |     |  | Sonnet       |
       |  cache)    |  |     |  | (LangGraph   |
       +------------+  +-----+  |  agent)      |
                                 +--------------+
```

---

## iOS App

**Target**: iOS 16.0+, Swift 5.9, SwiftUI
**Bundle ID**: `com.24defend.app`
**Packet Tunnel Bundle ID**: `com.24defend.app.packet-tunnel`
**App Group**: `group.com.24defend.app`
**Project generation**: XcodeGen (`ios/project.yml`)

### Targets

| Target | Type | Purpose |
|--------|------|---------|
| TwentyFourDefend | Application | Main app: dashboard, settings, block log |
| TwentyFourDefendPacketTunnel | App Extension | NEPacketTunnelProvider DNS filter |

Both targets share code in the `Shared/` directory (APIClient, BloomFilter, BloomFilterStore, BKTree, DomainChecker, BrandRuleEngine, BlockLog, PendingInvestigation, DailyBlacklist, TelemetryClient, PhishingClassifier, DNSCache). The ML classifier (Layer 7) runs as a silent screener -- it submits suspicious domains to the API in the background and tracks them via PendingInvestigation for retroactive notification if confirmed malicious.

### PacketTunnelProvider DNS Interception Flow

The packet tunnel configures itself as the device's DNS resolver by setting up a TUN interface at `198.18.0.1` and pointing all DNS queries to it via `NEDNSSettings(servers: ["198.18.0.1"])` with `matchDomains = [""]` (match all).

```
All DNS queries (port 53)
         |
         v
   PacketTunnelProvider.handlePacket()
         |
         v
   Parse IPv4/UDP/DNS layers (IPPacket + DNSPacket)
         |
         v
   Extract domain name from DNS query
         |
         v
   Run 10+ layer check (see below)
         |
    +----+----+
    |         |
  BLOCK     ALLOW
    |         |
    v         v
  Build DNS     Forward query to
  response:     upstream DNS (1.1.1.1)
  127.0.0.1     via NWConnection/UDP
  (sinkhole)
    |
    v
  Block page served
  on 127.0.0.1:80
```

When a domain is blocked, the DNS response resolves to `127.0.0.1`. A local HTTP server running on port 80 inside the tunnel extension serves a Spanish-language block page ("Sitio bloqueado -- 24Defend"). An HTTPS listener on port 443 immediately rejects connections to force Safari to fall back to HTTP.

### 10+ Layer Check Order

Each DNS query runs through these checks in order. The first match wins.

```
Layer 0: DNS verdict cache (LRU, 2K entries, 1hr TTL)
   |  If cached: return cached allow/block immediately (<0.01ms).
   v
Layer 1: Runtime blacklist (in-memory Set<String>)
   |  Domains confirmed bad by the backend during this session.
   |  Source: backend /check verdict = "block" (added after API escalation).
   |  Result: BLOCK (red notification)
   v
Layer 2: Infrastructure allowlist (DomainChecker.isInfrastructureDomain)
   |  Known CDN/platform domains (Apple, Google, Cloudflare, Akamai, etc.)
   |  skip all detection. Hardcoded in DomainChecker.
   |  If match: ALLOW silently, skip all further checks.
   v
Layer 3: Bloom filter whitelist
   |  Downloaded from backend, cached in App Group UserDefaults.
   |  Checks base domain (e.g., homebanking.brou.com.uy -> brou.com.uy).
   |  If match: ALLOW silently, skip all further checks.
   v
Layer 4: Dual bloom filter blacklist (A + B) with API confirmation
   |  Two independent bloom filters with different hash parameters.
   |  Both downloaded from backend, cached in App Group UserDefaults.
   |  Checks base domain against known-bad domains.
   |  Combined false positive rate: ~1 in 670,000.
   |  If BOTH filters match:
   |    a. Check local false-positive list first (instant).
   |    b. If in FP list: ALLOW, skip further checks.
   |    c. If not in FP list: confirm with backend API (DynamoDB lookup, ~50ms).
   |    d. If API says block: BLOCK (red notification), add to runtime blacklist.
   |    e. If API says allow: forward DNS, record as false positive.
   |  Never blocks on bloom filter alone. Eliminates all bloom filter false positives.
   v
Layer 4b: Daily blacklist (fetched from /daily-blacklist every 30 min)
   |  Domains the backend agent confirmed as malicious in the last 48 hours.
   |  Polled alongside bloom filters. Stored in App Group UserDefaults.
   |  If match: BLOCK immediately (red notification).
   v
Layer 5: BK-tree Levenshtein fuzzy match
   |  a) Exact match against hardcoded blacklist Set -> BLOCK
   |  b) Subdomain of hardcoded blacklist entry -> BLOCK
   |  c) Exact/subdomain match against hardcoded whitelist -> ALLOW
   |  d) BK-tree Levenshtein search (max distance 3, similarity >= 70%)
   |     against whitelist base domains -> WARN
   v
Layer 6: Brand Rule Engine (BrandRuleEngine.swift)
   |  On-device brand impersonation detection. Runs in <1ms, no network.
   |  Checks for:
   |    - Uruguay brand keywords (25 brands: banks, fintech, telecom, govt)
   |    - Spanish phishing vocabulary (40+ words)
   |    - Brand + phishing word combinations (strongest signal)
   |    - TLD risk scoring (high-risk vs low-risk TLDs)
   |    - Structural signals (hyphens, digits, domain length)
   |    - Year patterns (e.g., brou-2026, itau2025)
   |  Returns RiskAssessment with score (0.0-1.0) and signal list.
   |  If score >= 0.7 (high risk) -> WARN
   v
Layer 7: ML classifier (silent screener)
   |  Logistic regression, 1 KB model, 20 features extracted from domain string.
   |  AUC 0.9974 on synthetic validation set.
   |  All features computable from the domain string alone, no network calls.
   |  Runs in <1ms. Model weights shipped as JSON, updated via CDN.
   |  SILENT: never shows user-facing warnings from ML model.
   |  If score >= 0.5 -> submit domain to API in background for investigation.
   |  No user warning, no DNS hold. Only brand rule engine warnings are user-facing.
   |  Domain added to PendingInvestigation for retroactive notification polling.
   |
   |  If WARN from Layer 5 or 6: hold the DNS query and call backend API (Layer 8)
   v
Layer 8: Backend API call (POST /check)
   |  Only reached for WARN verdicts from Layers 5/6.
   |  Also called for bloom filter confirmations (Layer 4) and ML submissions (Layer 7).
   |  Async: DNS query is held while waiting for response (for WARN verdicts).
   |  If backend returns "block": escalate to BLOCK, add to runtime blacklist.
   |  If backend returns "allow"/"warn" or is unreachable: ALLOW with yellow warning.
   v
Done

### Retroactive investigation notifications

When the ML classifier silently submits a domain (Layer 7), the first user's DNS is
forwarded — they see the page. The domain is added to PendingInvestigation, which polls
POST /check every 30 seconds for up to 10 minutes.

If the backend agent confirms the domain is malicious:
- A forced push notification is sent: "Sitio peligroso confirmado — Si ingresaste
  datos personales, cambia tu contrasena."
- The domain is added to the runtime blacklist (blocked on any future visit)
- Logged to the Alert Log and telemetry (layer: "investigation")

This protects the "first user" — the one who visits a novel phishing domain before it
appears in any blacklist. They receive a retroactive warning within ~30-60 seconds
instead of never being notified.

Max 20 pending investigations, entries expire after 10 minutes.
```

### BloomFilterStore

Manages downloading, caching, and accessing bloom filters.

- **Storage**: App Group UserDefaults (`group.com.24defend.app`)
- **Refresh**: on tunnel start if >24 hours since last fetch
- **Download**: fetches from `GET /admin/bloom-filter/whitelist`, `/blacklist`, and `/blacklist-b`
- **Daily lists**: fetches `/daily-blacklist` and `/daily-false-positives` every 30 minutes. The false-positive list is checked locally before making API confirmation calls for bloom filter hits.
- **Bypass**: uses a URLSession with empty `connectionProxyDictionary` to bypass the tunnel itself
- **Base domain extraction**: mirrors backend logic, including two-part TLD handling for LatAm ccTLDs (`.com.uy`, `.com.ar`, `.com.br`, `.com.mx`, `.com.co`, `.com.cl`, etc.)

### BloomFilter Binary Format

```
[4 bytes: m (filter size, big-endian)] [4 bytes: k (hash count, big-endian)] [bitarray bytes]
```

Hash function: MurmurHash3 32-bit with seed `i` for `i` in `0..<k`. The Swift implementation is a manual port that matches Python's `mmh3.hash(key, seed=i)`.

### BKTree

A BK-tree (Burkhard-Keller tree) built from whitelist base domains for efficient fuzzy string matching:

- **Insert**: O(log n) average
- **Search**: O(log n) average via triangle inequality pruning
- **Distance metric**: Levenshtein edit distance (optimized single-row algorithm)
- **Query**: find all whitelist domains within edit distance 3 of the queried domain
- **Threshold**: similarity >= 70% triggers a WARN verdict

### BrandRuleEngine

On-device brand impersonation detector (`Shared/BrandRuleEngine.swift`) that catches phishing domains Levenshtein matching misses -- for example, `actualizacion-brou-2026.com` does not have a low edit distance to `brou.com.uy`, but it clearly impersonates the brand.

**Scoring components** (additive, capped at 1.0):

| Signal | Score | Example |
|--------|-------|---------|
| Brand keyword present (not alone) | +0.35 | `brou` in `brou-seguro.com` |
| Phishing vocabulary word | +0.20 | `verificar` in `itau-verificar.xyz` |
| Brand + phishing word combo | +0.25 | `brou` + `actualizacion` |
| High-risk TLD | +0.15 | `.xyz`, `.top`, `.click`, `.tk` |
| Brand on high-risk TLD | +0.15 | `brou` on `.xyz` |
| Multiple hyphens (>=2) | +0.10 | `brou-seguro-login.com` |
| Many digits (>=3) | +0.05 | `brou123.com` |
| Long name (>25 chars) | +0.05 | Very long domain names |
| Brand + year pattern | +0.15 | `brou-2026`, `itau2025` |

**Thresholds**: score >= 0.7 is high risk (triggers WARN verdict), score >= 0.4 is suspicious.

**Brand keywords** (25 Uruguay brands):
- Banks: brou, bancorepublica, itau, santander, scotiabank, bbva, hsbc, heritage, bandes
- Fintech/payments: prex, oca, visa, mastercard, mercadopago, mercadolibre
- Services: pedidosya, abitab, redpagos
- Telecom: antel, movistar, claro
- Government: bps, dgi, agesic, gub

**Phishing vocabulary** (40+ Spanish words): action words (actualizar, verificar, confirmar, desbloquear), urgency (urgente, suspension, bloqueo, vencido), credential terms (homebanking, clave, token, tarjeta), security theater (seguro, proteccion, alerta), login patterns (login, signin, ingreso).

**TLD classification**:
- High-risk: xyz, top, click, buzz, gq, ml, cf, tk, pw, cc, club, icu, cam, link, online, site, info, and others
- Low-risk (Uruguay): com.uy, uy, gub.uy, edu.uy, org.uy, mil.uy

### Notifications

Two severity levels:

| Severity | Color | Trigger | Title | Behavior |
|----------|-------|---------|-------|----------|
| Red | Red | Daily blacklist hit, bloom filter API-confirmed block, or backend-confirmed block | "Phishing link blocked" | Domain is blocked |
| Yellow | Yellow | Brand rule engine or Levenshtein similarity to official domain | "Suspicious link detected" | Domain is allowed with warning |

Notifications are debounced: one notification per domain per tunnel session. Tapping a notification opens a `BlockDetailView` sheet with details in Spanish.

**Smart notification suppression**: Notifications are heavily filtered to avoid noise. The principle is "silence is the default state" -- DNS blocking and telemetry recording are unaffected, only the user-facing notification is suppressed.

- **Brand keyword filter**: only notify for domains containing a brand keyword (brou, itau, santander, etc.). Generic blacklist blocks (ad trackers, CDN malware, background app requests) are silenced.
- **Page resource window**: suppress notifications within 3 seconds of a whitelist hit. This catches invisible page resources (ad trackers, analytics) loaded when visiting a legitimate site.
- **Rate limit**: max 1 notification per 5 seconds.

**Key insight**: visiting yahoo.com triggered 10+ notifications for invisible ad tracker domains. These were legitimate blacklist entries (threat feeds flag ad networks for malvertising), but DNS-level blocking cannot distinguish good vs bad content on shared infrastructure. The fix is two-fold: filter shared infrastructure at ingestion and suppress notifications for non-brand domains.

### Block Log

Persisted via App Group UserDefaults as JSON-encoded `[BlockEvent]`. Maximum 200 entries, newest first. Shared between the packet tunnel extension (writes) and the main app (reads/displays).

### Views

| View | Purpose |
|------|---------|
| `DashboardView` | Shield icon, VPN toggle, 3 most recent alerts |
| `BlockLogView` | Full scrollable list of all alerts with severity dots |
| `BlockDetailView` | Modal detail for a single blocked/warned domain |

---

## Backend API

**Tech stack**: Python 3.12, FastAPI, aioboto3, LangGraph, LangChain, AWS Bedrock
**Port**: 8080
**Docs**: `/docs` (Swagger UI)

### Endpoints

#### Public

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/check` | Check a domain. Returns verdict (block/warn/allow), confidence, reason, source. |
| GET | `/health` | Health check |
| GET | `/daily-blacklist` | Domains confirmed malicious in last 48h. Polled by devices every 30 min. |
| GET | `/daily-false-positives` | Bloom filter false positives (verdict=allow) checked in last 48h. Public, no auth. Devices poll every 30 min alongside daily blacklist. Prevents repeated API calls for known FPs. |

#### Admin (requires `X-Api-Key` header)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/admin/domains` | Bulk add domains to blacklist or whitelist |
| DELETE | `/admin/domains/{domain}` | Remove a domain from any list |
| GET | `/admin/domains` | List domains by entry_type, optional partner_id filter |
| POST | `/admin/ingest/blacklists` | Trigger blacklist feed ingestion |
| POST | `/admin/ingest/whitelist-discovery` | Auto-discover subdomains via CT logs |
| GET | `/admin/bloom-filter/whitelist` | Download whitelist bloom filter (binary) |
| GET | `/admin/bloom-filter/blacklist` | Download blacklist bloom filter A (binary) |
| GET | `/admin/bloom-filter/blacklist-b` | Download blacklist bloom filter B (binary) |
| GET | `/admin/bloom-filter/stats` | Bloom filter statistics |
| POST | `/admin/bloom-filter/regenerate` | Manually regenerate bloom filters |
| POST | `/admin/jobs/run-daily` | Manually trigger the daily job |

### POST /check Flow

```
1. Normalize domain (lowercase, strip trailing dots)
2. Look up in DynamoDB:
   a. Try exact match
   b. Try without www. prefix
   c. Walk up parent domains (sub.evil.com -> evil.com)
3. If found:
   - blacklist entry -> verdict: block, confidence: 1.0
   - whitelist entry -> verdict: allow, confidence: 1.0
   - cache entry -> return cached verdict + confidence
4. If not found:
   -> Run LangGraph investigation agent
   -> Cache result in DynamoDB (TTL: 30 days)
   -> Return verdict
```

### LangGraph Investigation Agent

A LangGraph-based agent using AWS Bedrock Claude Sonnet as the reasoning engine. The agent autonomously decides which tools to call and interprets results to produce a structured verdict.

**LLM**: `us.anthropic.claude-sonnet-4-6` (configurable via `DEFEND_BEDROCK_MODEL_ID`)
**Temperature**: 0
**Max tokens**: 1024

**Graph structure**:

```
  +-------+
  | agent |<---------+
  +---+---+          |
      |              |
      v              |
  has tool calls?    |
   /        \        |
  yes        no      |
  |           |      |
  v           v      |
+-------+   END      |
| tools |             |
+---+---+             |
    |                 |
    +-----------------+
```

The agent loops: call LLM -> if LLM requests tool calls, execute them -> feed results back -> repeat until LLM produces a final JSON verdict.

**System prompt** instructs the agent to:
1. Start with `domain_heuristics` and `levenshtein_similarity` (instant, free)
2. Use `dns_lookup` for domain age
3. Use `ssl_certificate_check` for cert analysis
4. Use `google_search` for context
5. Use `safe_browsing_check` for definitive flags

**Tools** (defined in `app/investigation/tools.py`):

| Tool | What it does | Data source |
|------|-------------|-------------|
| `domain_heuristics` | String analysis: length, hyphens, digits, TLD risk, subdomain depth, entropy, brand keyword detection, Spanish phishing vocabulary, brand+phishing combos, year patterns | Pure computation |
| `levenshtein_similarity` | Edit distance to whitelist domains; detects typosquatting | Whitelist from DynamoDB |
| `dns_lookup` | Domain age, registrar, nameservers via RDAP | rdap.org (free, no API key) |
| `ssl_certificate_check` | Certificate issuer, age, SANs, validity | Direct TLS connection |
| `google_search` | Web presence check via Serper API | google.serper.dev (requires API key) |
| `safe_browsing_check` | Google Safe Browsing status | transparencyreport.google.com |

**Output format**: JSON with `verdict` (block/warn/allow), `confidence` (0.0-1.0), and `reasoning`.

**Caching**: Results cached in DynamoDB as `entry_type=cache` with TTL:
- Normal verdicts: 30 days
- Unclear verdicts (parse failure): 7 days
- Failed investigations: 1 hour

**Fallback agent** (`app/agent.py`): A simpler non-LLM agent that runs concurrently: RDAP age check, SSL cert check, and heuristics. Produces a score-based verdict. This was the original implementation before the LangGraph agent.

### Domain Service (DynamoDB CRUD)

Single-table design with `domain` as the hash key.

**Entry types**:

| entry_type | Purpose | Fields |
|-----------|---------|--------|
| `blacklist` | Known phishing domains | domain, reason |
| `whitelist` | Verified safe domains | domain, partner_id, reason |
| `cache` | Agent investigation results | domain, verdict, confidence, reason, checked_at, ttl |

**Operations**: `lookup_domain`, `put_domain`, `put_domains_bulk` (batch writer, chunks of 25), `delete_domain`, `scan_by_type` (with optional partner_id filter).

### Bloom Filter Generation

Three bloom filters, all using **base domains only** (subdomains stripped):

- **Whitelist bloom**: known-safe base domains. On-device: match -> silent allow.
- **Blacklist bloom A**: known-bad base domains. First of the dual blacklist filters.
- **Blacklist bloom B**: same domain set as A but different hash parameters/FP rate.

The dual blacklist filters (A + B) achieve a combined false positive rate of approximately 1 in 670,000. On-device, a domain must match BOTH filters to be considered a bloom hit. Even then, the device confirms with the backend API (POST /check) before blocking -- bloom filter alone never blocks. If the API confirms "allow", the domain is added to the daily false-positive list.

**Base domain extraction** handles LatAm two-part TLDs:
- `homebanking.brou.com.uy` -> `brou.com.uy`
- `www.google.com` -> `google.com`
- `sub.evil.xyz` -> `evil.xyz`

Two-part TLDs recognized: `com.uy`, `com.ar`, `com.br`, `com.mx`, `com.co`, `com.cl`, `co.uk`, `com.au`, `com.pe`, `com.py`, `com.bo`, `com.ve`, `com.ec`, `com.pa`, `com.gt`, `com.cr`, `com.do`, `com.sv`, `com.hn`, `com.ni`, `gob.uy`, `org.uy`, `edu.uy`, `net.uy`.

**Algorithm**: Standard bloom filter with optimal parameters calculated from item count and target false positive rate (default 0.1%). Hash function: MurmurHash3 with seeds 0 through k-1.

**Binary format**: `[4 bytes: m] [4 bytes: k] [bitarray bytes]` (big-endian).

**Storage**: Written to disk at `DEFEND_BLOOM_DIR` (default `/app/data/bloom`). Served via admin endpoints.

### Ingestion (Threat Feed Sources)

Four public threat intelligence feeds ingested concurrently:

| Source | URL | Format | Update frequency |
|--------|-----|--------|------------------|
| OpenPhish | `openphish.com/feed.txt` | Plain text, one URL per line | Continuous |
| PhishTank | `data.phishtank.com/data/online-valid.csv` | CSV | Hourly |
| URLhaus (abuse.ch) | `urlhaus.abuse.ch/downloads/csv_online/` | CSV | Every 5 minutes |
| Phishing.Army | `phishing.army/download/phishing_army_blocklist.txt` | Plain text, one domain per line | Daily |

**Ingestion flow**:
1. Fetch all sources concurrently (tolerates individual failures)
2. Extract domains from URLs (strip protocol, path, port, query, fragment)
3. Filter out shared infrastructure domains using the Majestic Million top 100K list (downloaded at ingestion time, ~15MB CSV). Any blacklist domain whose base domain appears in the top 100K is excluded -- these host both legitimate and malicious content, and blocking at DNS level breaks pages. Falls back to a hardcoded 43-domain `SHARED_INFRASTRUCTURE_DOMAINS` set in `backend/app/ingestion/runner.py` if the download fails.
4. Deduplicate across all sources
5. Skip domains already in DynamoDB (blacklist, whitelist, or cache)
6. Batch insert new domains as `entry_type=blacklist`

**Whitelist auto-discovery**: Certificate Transparency logs via `crt.sh`. Given a root domain (e.g., `brou.com.uy`), discovers all subdomains from CT logs and adds them as whitelist entries with a partner_id. Wildcards (`*.domain`) are excluded.

### Scheduler

APScheduler runs a daily job at 03:00 UTC:

1. Ingest all public blacklist feeds
2. Regenerate all three bloom filters (whitelist, blacklist A, blacklist B) and write to disk

On startup, the same ingestion + bloom generation runs as a non-blocking background task via `asyncio.create_task()`. The server starts accepting requests immediately without waiting for ingestion to complete. The table and whitelist cache are loaded synchronously during lifespan startup; only the slower feed ingestion and bloom filter generation are deferred.

---

## ML Pipeline

A lightweight ML classifier trained to detect phishing domains from string-level features alone, designed for on-device inference with no network calls.

### Synthetic Data Generation

Training data is generated synthetically using 7 attack patterns derived from LatAm/Uruguay phishing research (`ml/generate_synthetic.py`):

| Pattern | Description | Example |
|---------|-------------|---------|
| 1. Brand + action | Brand name combined with phishing action word | `brou-verificar.xyz` |
| 2. TLD swap | Official `.com.uy` brand on a different TLD | `itau.top`, `brou-uy.click` |
| 3. Homoglyphs | Character substitution (0 for o, 1 for i/l, etc.) | `br0u.com.uy`, `1tau.com` |
| 4. Subdomain trick | Brand buried in subdomain of attacker domain | `brou.com.uy.secure-login.xyz` |
| 5. Urgency combo | Brand + urgency vocabulary + optional year | `alerta-brou-suspension.top` |
| 6. Year + brand | Year appended to brand | `brou-2026.xyz` |
| 7. Service subdomain | Mimics real service subdomains | `homebanking-brou.net` |

Default dataset: 1,500 phishing domains per pattern (10,500 total) + 7,000 legitimate domains = 17,500 domains. Legitimate domains include Uruguayan media, e-commerce, tech, social, education, and random plausible names.

### Feature Extraction

20 features extracted from the domain string alone (`ml/features.py`), all computable in <1ms with no network calls:

| # | Feature | Description |
|---|---------|-------------|
| 1 | `domain_length` | Total length of the domain string |
| 2 | `name_length` | Length without TLD |
| 3 | `dot_count` | Number of dots |
| 4 | `hyphen_count` | Number of hyphens in the name part |
| 5 | `digit_count` | Number of digits in the name part |
| 6 | `digit_ratio` | Ratio of digits to name length |
| 7 | `unique_char_ratio` | Character diversity (entropy proxy) |
| 8 | `consonant_ratio` | Ratio of consonants to name length |
| 9 | `max_consecutive_consonants` | Longest consonant run |
| 10 | `has_brand` | 1 if contains a UY brand keyword (22 brands) |
| 11 | `brand_count` | Number of brand keywords found |
| 12 | `has_phishing_word` | 1 if contains a Spanish phishing vocabulary word |
| 13 | `phishing_word_count` | Number of phishing words found |
| 14 | `brand_phishing_combo` | 1 if both brand + phishing word present |
| 15 | `has_year_pattern` | 1 if contains 202X |
| 16 | `brand_year_combo` | 1 if brand + year pattern |
| 17 | `tld_risk` | 1.0 = high risk, 0.0 = low risk, 0.5 = neutral |
| 18 | `brand_on_risky_tld` | 1 if brand keyword on a high-risk TLD |
| 19 | `has_homoglyph` | 1 if digits could be letter substitutions near a brand |
| 20 | `subdomain_depth` | Number of dots beyond the base domain |

### Models

Two models are trained (`ml/train.py`), both using scikit-learn:

| Model | Algorithm | Size | Purpose | AUC |
|-------|-----------|------|---------|-----|
| Logistic regression | `LogisticRegression` (C=1.0) | 1 KB | On-device (Layer 6) | 0.9974 |
| Gradient boosting | `GradientBoostingClassifier` (100 trees, depth 4) | 238 KB | Backend enrichment | 0.9974+ |

Both models are exported as JSON (`ml/models/`) containing weights, coefficients, and tree structures for portable inference in Swift or Python without scikit-learn.

**Top features by importance** (GBM feature importances): `brand_phishing_combo`, `has_phishing_word`, `phishing_word_count`, `has_brand`, `brand_on_risky_tld`, `tld_risk`, `digit_count`, `hyphen_count`, `domain_length`, `has_year_pattern`.

### Metrics

Evaluated on a held-out 20% test split (stratified):

- **AUC-ROC**: 0.9974
- **5-fold CV AUC**: 0.9974
- **Precision (phishing)**: >0.99
- **Recall (phishing)**: >0.99
- **Confusion matrix**: very low false positive and false negative rates

### Caveats

The model is trained entirely on synthetic data. While the attack patterns are based on real-world LatAm phishing research, performance on real-world traffic may differ. Real-world validation is planned via 1% active learning sampling (see below).

### Active Learning Loop (Planned)

To improve the model with real-world data:

```
Device traffic (DNS queries)
   |
   v
1% of domains not matched by Layers 1-5 are sampled
   |
   v
Sampled domains sent to backend (POST /check)
   |
   v
LangGraph investigation agent produces verdict
   |
   v
Verdict stored as labeled training data
   |
   v
Monthly retrain: synthetic + real-world labels
   |
   v
Updated model weights (JSON) shipped via CDN
   |
   v
iOS app downloads new weights on next bloom filter refresh
```

This creates a feedback loop where the backend agent's investigations produce high-quality labels for domains the on-device model is uncertain about, progressively improving coverage of real attack patterns not represented in synthetic data.

### Retraining Schedule

- **Frequency**: Monthly, or ad-hoc when new attack patterns are identified
- **Data**: Synthetic dataset + accumulated real-world labels from active learning
- **Output**: Updated `phishing_classifier_logistic.json` (1 KB) pushed to CDN
- **Validation**: AUC must exceed 0.99 on held-out test set before shipping

---

## Data Flow: Phishing Link Clicked

Step-by-step walkthrough of what happens when a user taps a phishing link (e.g., `brou-seguro.com` impersonating BROU bank):

```
1. User taps link in SMS/WhatsApp/email
   |
2. iOS resolves DNS for brou-seguro.com
   |
3. DNS query (UDP port 53) routed to PacketTunnelProvider
   |
4. PacketTunnelProvider.handlePacket() parses the IPv4/UDP/DNS packet
   |
5. Layer 0: DNS verdict cache -> NOT CACHED (first time)
   |
6. Layer 1: Check runtime blacklist -> NOT FOUND (first time seeing this domain)
   |
7. Layer 2: Infrastructure allowlist -> NOT an infrastructure domain
   |
8. Layer 3: Check bloom whitelist for base domain "brou-seguro.com" -> NOT FOUND
   |
9. Layer 4: Check dual bloom blacklist for base domain "brou-seguro.com"
   |  -> BOTH filters match (brou-seguro.com was ingested from PhishTank/OpenPhish)
   |  -> Check local FP list -> NOT FOUND
   |  -> Confirm with API: POST /check -> verdict: "block"
   |
11. BLOCKED:
   a. DNS response: brou-seguro.com -> 127.0.0.1
   b. Browser requests HTTP to 127.0.0.1
   c. Block page server returns Spanish "Sitio bloqueado" HTML page
   d. Domain added to runtime blacklist
   e. BlockLog.append() records the event (red severity)
   f. Push notification: "Phishing link blocked"
   g. User sees block page in browser + notification banner
```

If the domain is NOT in the bloom blacklist but is similar to a whitelisted domain (e.g., `br0u.com.uy` with a zero instead of 'o'):

```
1-8. Same as above, bloom filters don't match
   |
9. Layer 5: DomainChecker.check()
   a. Not in hardcoded blacklist
   b. Not in hardcoded whitelist
   c. BK-tree search: "br0u.com.uy" vs "brou.com.uy" -> distance 1, similarity 90%
   d. Result: WARN (Layers 6-7 skipped, already WARN)
   |
10. Layer 8: Hold DNS, call POST /check with domain "br0u.com.uy"
   |
12. Backend: not in DynamoDB -> run LangGraph agent
   a. Agent calls domain_heuristics: "Contains brand name: brou"
   b. Agent calls levenshtein_similarity: "brou.com.uy: distance=1, similarity=91%"
   c. Agent calls dns_lookup: "Domain registered 3 days ago (very new)"
   d. Agent calls ssl_certificate_check: "Free CA (Let's Encrypt), cert 2 days old"
   e. Agent verdict: {"verdict": "block", "confidence": 0.95, "reasoning": "..."}
   |
13. Backend caches result in DynamoDB (TTL 30 days)
    |
14. iOS receives "block" verdict:
    a. Domain added to runtime blacklist
    b. DNS response: br0u.com.uy -> 127.0.0.1
    c. Block page served
    d. Red notification: "Phishing link blocked"
```

---

## Infrastructure

### Local Development

```
docker-compose.yml
  |
  +-- api (FastAPI on port 9147)
  |     Dockerfile: python:3.12-slim + uvicorn
  |
  +-- dynamodb-local (amazon/dynamodb-local, in-memory, port 8000)
```

Start locally:
```bash
cd backend
docker compose up --build
# API at http://localhost:9147
# Docs at http://localhost:9147/docs
```

Seed test data:
```bash
docker compose exec api python -m seed
```

The seed script populates:
- 8 blacklist domains (known phishing: brou-seguro.com, itau-homebanking.net, etc.)
- 15 whitelist domains with partner_ids (brou, itau, general institutions)

Seed Uruguay institution data (discovers subdomains via CT logs):
```bash
python3 scripts/seed_uruguay.py http://localhost:9147
```

The Uruguay seed script (`backend/scripts/seed_uruguay.py`) registers 24 institutions with their root domains, then discovers subdomains via Certificate Transparency logs (crt.sh). This produces approximately 652 whitelist domains covering:
- **Banks**: BROU, Itau, Santander, Scotiabank, BBVA, HSBC, Heritage, Bandes, Citibank
- **Payments/fintech**: OCA, Prex, MercadoPago, MercadoLibre
- **Payment networks**: Abitab, RedPagos
- **Telecom**: Antel, Movistar, Claro
- **E-commerce**: PedidosYa
- **Government**: GUB, BPS, DGI, BCU, AGESIC

### Production (planned)

- **Compute**: AWS Fargate (containerized FastAPI)
- **Database**: DynamoDB (PAY_PER_REQUEST billing, single table)
- **Storage**: S3 bucket `24defend-bloomfilter` (for bloom filter distribution)
- **AI**: AWS Bedrock (Claude Sonnet, us-east-1)
- **Search**: Serper API (optional, for Google search tool)

### iOS Build

```bash
cd ios
xcodegen generate        # Generate .xcodeproj from project.yml
open TwentyFourDefend.xcodeproj
```

Requires:
- Apple Developer Program ($99/year) for NetworkExtension entitlement
- `packet-tunnel-provider` entitlement (may need separate request from Apple)
- App Group capability (`group.com.24defend.app`)

See `ios/DISTRIBUTION.md` for TestFlight, Ad Hoc, and App Store distribution details.

---

## Configuration

All backend configuration is via environment variables with the `DEFEND_` prefix (managed by pydantic-settings).

| Variable | Default | Purpose |
|----------|---------|---------|
| `DEFEND_AWS_REGION` | `us-east-1` | AWS region for DynamoDB and S3 |
| `DEFEND_AWS_ACCOUNT_ID` | `487542878969` | AWS account (dev) |
| `DEFEND_AWS_PROFILE` | (none) | Named AWS profile (alternative to env vars) |
| `DEFEND_DYNAMODB_TABLE` | `24defend-domains` | DynamoDB table name |
| `DEFEND_DYNAMODB_ENDPOINT` | (none) | Override for local DynamoDB (e.g., `http://localhost:8000`) |
| `DEFEND_S3_BUCKET` | `24defend-bloomfilter` | S3 bucket for bloom filters |
| `DEFEND_BLOOM_FILTER_SIZE` | `100000` | Target bloom filter capacity |
| `DEFEND_BLOOM_FILTER_FP_RATE` | `0.001` | Target false positive rate (0.1%) |
| `DEFEND_BLOOM_DIR` | `/app/data/bloom` | Local directory for bloom filter files |
| `DEFEND_API_KEY` | `dev-api-key-change-me` | API key for admin endpoints |
| `DEFEND_BEDROCK_MODEL_ID` | `us.anthropic.claude-sonnet-4-6` | Bedrock model for investigation agent |
| `DEFEND_BEDROCK_REGION` | `us-east-1` | Bedrock region |
| `DEFEND_SERPER_API_KEY` | (none) | Serper API key for Google search tool (optional) |
| `DEFEND_ENV` | `dev` | Environment: `dev` or `prod` |

Standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) are also required for DynamoDB and Bedrock access.

---

## Security Model

### What data leaves the device

The system is designed to minimize data leaving the device:

1. **Bloom filter downloads** (startup + daily): the app fetches three binary bloom filter files (whitelist, blacklist A, blacklist B) plus two JSON lists (daily blacklist, daily false positives) from the backend. These are generic files, not user-specific. No user data is sent.

2. **Domain checks** (Layer 6 bloom confirmation + Layer 10): a domain name is sent to the backend when (a) the dual bloom filter matches and needs API confirmation, or (b) the on-device heuristics produce a WARN verdict (Levenshtein similarity or brand rule engine). The ML classifier submits suspicious domains in the background silently. This represents a small fraction of all DNS queries. The request contains only the domain name -- no user identifier, no URL path, no page content, no browsing history.

3. **No traffic routing**: despite using a VPN configuration, no user traffic is routed through external servers. The tunnel only intercepts DNS queries on port 53. All other traffic passes through normally. Allowed DNS queries are forwarded directly to Cloudflare's public resolver (1.1.1.1).

### What stays on the device

- All DNS queries for domains that match bloom filters (vast majority)
- All DNS queries for domains that pass DomainChecker without a WARN
- The block log (stored in App Group UserDefaults)
- Bloom filter data (cached in App Group UserDefaults)

### Authentication

- Admin endpoints require `X-Api-Key` header
- The `/check` endpoint has no authentication (called from the packet tunnel extension with no user identity)
- The iOS app's API client bypasses the VPN tunnel (`connectionProxyDictionary = [:]`) to avoid recursive interception

### Data retention

- Blacklist/whitelist entries: permanent until manually removed
- Cache entries (agent results): DynamoDB TTL, 30 days for normal verdicts, 7 days for unclear, 1 hour for failures
- Block log on device: last 200 events, newest first

---

## Testing

### Backend Tests

160+ unit tests across 5 test files, all using pytest with async support.

| File | Tests | Coverage |
|------|-------|----------|
| `test_check.py` | 12 | POST /check: blacklist/whitelist/cache hits, agent fallback, www stripping, parent domain lookup, normalization |
| `test_admin.py` | 21 | Admin endpoints: bulk add, delete, list, bloom filter serving/stats/regeneration, ingestion triggers, auth |
| `test_agent.py` | 40 | Levenshtein distance, base domain extraction, heuristic scoring, RDAP checks, SSL cert checks, full investigation flow |
| `test_bloom.py` | 26 | Base domain extraction (LatAm TLDs), optimal params, bloom build/check, serialization, async generation |
| `test_ingestion.py` | 32 | URL domain extraction, feed parsers (OpenPhish, PhishTank, URLhaus, Phishing.Army, crt.sh), aggregation, dedup, runner |

**Test infrastructure**:
- In-memory DynamoDB mock (`FakeTable` class in `conftest.py`) -- no external dependencies
- FastAPI test client via `httpx.AsyncClient` with `ASGITransport`
- All external HTTP calls (RDAP, SSL, feeds) mocked via `unittest.mock.patch`

### Running Tests

```bash
cd backend

# Install test dependencies
pip install -r requirements.txt -r requirements-test.txt

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_check.py

# Run a specific test class or method
pytest tests/test_agent.py::TestCheckHeuristics::test_risky_tld
```

Configuration in `pytest.ini`:
```ini
[pytest]
asyncio_mode = auto
testpaths = tests
```

---

## File Structure

```
24defend-mono/
|
+-- backend/
|   +-- app/
|   |   +-- main.py                  # FastAPI app, lifespan, startup tasks
|   |   +-- config.py                # DEFEND_* env var settings
|   |   +-- models.py                # Pydantic models (DomainEntry, Verdict, etc.)
|   |   +-- db.py                    # DynamoDB client (aioboto3)
|   |   +-- auth.py                  # X-Api-Key header validation
|   |   +-- domain_service.py        # DynamoDB CRUD operations
|   |   +-- bloom.py                 # Bloom filter build/check + base domain extraction
|   |   +-- agent.py                 # Fallback investigation agent (non-LLM)
|   |   +-- scheduler.py             # APScheduler daily job (03:00 UTC)
|   |   +-- routes/
|   |   |   +-- check.py             # POST /check endpoint
|   |   |   +-- admin.py             # /admin/* endpoints
|   |   +-- investigation/
|   |   |   +-- graph.py             # LangGraph agent (Bedrock Sonnet)
|   |   |   +-- tools.py             # 6 agent tools (DNS, SSL, Levenshtein, etc.)
|   |   +-- ingestion/
|   |       +-- sources.py           # Threat feed fetchers (4 sources + crt.sh)
|   |       +-- runner.py            # Ingestion orchestration + dedup
|   +-- tests/
|   |   +-- conftest.py              # FakeTable, test client, fixtures
|   |   +-- test_check.py            # 12 tests
|   |   +-- test_admin.py            # 21 tests
|   |   +-- test_agent.py            # 40 tests
|   |   +-- test_bloom.py            # 26 tests
|   |   +-- test_ingestion.py        # 32 tests
|   +-- seed.py                      # Seed script for local dev
|   +-- scripts/
|   |   +-- seed_uruguay.py          # Seed 24 UY institutions + CT log discovery
|   +-- Dockerfile                   # python:3.12-slim + uvicorn
|   +-- docker-compose.yml           # API + DynamoDB local
|   +-- requirements.txt             # Production dependencies
|   +-- requirements-test.txt        # Test dependencies (pytest, httpx)
|   +-- pytest.ini
|
+-- ios/
|   +-- project.yml                  # XcodeGen project definition
|   +-- Shared/                      # Code shared between app and extension
|   |   +-- APIClient.swift          # HTTP client for POST /check
|   |   +-- BloomFilter.swift        # Bloom filter + BloomFilterStore
|   |   +-- BKTree.swift             # BK-tree for fuzzy string matching
|   |   +-- DomainChecker.swift      # 7-layer domain check logic
|   |   +-- BrandRuleEngine.swift   # Uruguay brand impersonation detector
|   |   +-- BlockLog.swift           # Persisted block event log
|   +-- TwentyFourDefend/            # Main app target
|   |   +-- TwentyFourDefendApp.swift
|   |   +-- VPN/VPNManager.swift     # NEVPNManager wrapper
|   |   +-- Views/
|   |       +-- DashboardView.swift
|   |       +-- BlockLogView.swift
|   |       +-- BlockDetailView.swift
|   +-- TwentyFourDefendPacketTunnel/ # Network extension target
|   |   +-- PacketTunnelProvider.swift # DNS interception + block page server
|   |   +-- DNSPacket.swift           # DNS/IP/UDP packet parsing + construction
|   +-- DISTRIBUTION.md              # Apple Developer setup and distribution guide
|
+-- ml/
|   +-- generate_synthetic.py        # Synthetic phishing domain generator (7 attack patterns)
|   +-- features.py                  # 20-feature extraction from domain strings
|   +-- train.py                     # Train logistic + GBM classifiers
|   +-- models/
|   |   +-- phishing_classifier_logistic.json  # 1 KB, for on-device (Layer 6)
|   |   +-- phishing_classifier_gbm.json       # 238 KB, for backend enrichment
|   +-- data/                        # Generated training data (not committed)
|       +-- synthetic_domains.csv
|
+-- README.md
+-- architecture.md                  # This file
```

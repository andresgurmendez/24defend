# 24Defend Architecture

Anti-phishing link protection for mobile devices, targeting Latin America.

24Defend intercepts DNS queries on iOS devices using a NetworkExtension packet tunnel, checks domains against layered on-device filters (bloom filters, BK-tree fuzzy matching, hardcoded lists), and escalates uncertain domains to a backend investigation agent powered by AWS Bedrock Claude Sonnet. The system ingests public threat feeds daily and generates compact bloom filters that the iOS app downloads for offline protection.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [iOS App](#ios-app)
3. [Backend API](#backend-api)
4. [Data Flow: Phishing Link Clicked](#data-flow-phishing-link-clicked)
5. [Infrastructure](#infrastructure)
6. [Configuration](#configuration)
7. [Security Model](#security-model)
8. [Testing](#testing)

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
|  | - Block log      |   | - 5-layer check  |  |
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

Both targets share code in the `Shared/` directory (APIClient, BloomFilter, BloomFilterStore, BKTree, DomainChecker, BlockLog).

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
   Run 5-layer check (see below)
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

### 5-Layer Check Order

Each DNS query runs through these checks in order. The first match wins.

```
Layer 1: Runtime blacklist (in-memory Set<String>)
   |  Domains confirmed bad by the backend during this session.
   |  Source: backend /check verdict = "block" (added after Layer 4 escalation).
   |  Result: BLOCK (red notification)
   v
Layer 2: Bloom filter whitelist
   |  Downloaded from backend, cached in App Group UserDefaults.
   |  Checks base domain (e.g., homebanking.brou.com.uy -> brou.com.uy).
   |  If match: ALLOW silently, skip all further checks.
   v
Layer 3: Bloom filter blacklist
   |  Same download/cache mechanism as whitelist.
   |  Checks base domain against known-bad domains.
   |  If match: BLOCK immediately (red notification), no API call.
   v
Layer 4: DomainChecker (on-device heuristics + BK-tree)
   |  a) Exact match against hardcoded blacklist Set -> BLOCK
   |  b) Subdomain of hardcoded blacklist entry -> BLOCK
   |  c) Exact/subdomain match against hardcoded whitelist -> ALLOW
   |  d) BK-tree Levenshtein search (max distance 3, similarity >= 70%)
   |     against whitelist base domains -> WARN
   |  e) No match -> ALLOW
   |
   |  If WARN: hold the DNS query and call backend API (Layer 5)
   v
Layer 5: Backend API call (POST /check)
   |  Only reached for WARN verdicts from Layer 4.
   |  Async: DNS query is held while waiting for response.
   |  If backend returns "block": escalate to BLOCK, add to runtime blacklist.
   |  If backend returns "allow"/"warn" or is unreachable: ALLOW with yellow warning.
   v
Done
```

### BloomFilterStore

Manages downloading, caching, and accessing bloom filters.

- **Storage**: App Group UserDefaults (`group.com.24defend.app`)
- **Refresh**: on tunnel start if >24 hours since last fetch
- **Download**: fetches from `GET /admin/bloom-filter/whitelist` and `/blacklist`
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

### Notifications

Two severity levels:

| Severity | Color | Trigger | Title | Behavior |
|----------|-------|---------|-------|----------|
| Red | Red | Blacklist hit or backend-confirmed block | "Phishing link blocked" | Domain is blocked |
| Yellow | Yellow | Levenshtein similarity to official domain | "Suspicious link detected" | Domain is allowed with warning |

Notifications are debounced: one notification per domain per tunnel session. Tapping a notification opens a `BlockDetailView` sheet with details in Spanish.

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

#### Admin (requires `X-Api-Key` header)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/admin/domains` | Bulk add domains to blacklist or whitelist |
| DELETE | `/admin/domains/{domain}` | Remove a domain from any list |
| GET | `/admin/domains` | List domains by entry_type, optional partner_id filter |
| POST | `/admin/ingest/blacklists` | Trigger blacklist feed ingestion |
| POST | `/admin/ingest/whitelist-discovery` | Auto-discover subdomains via CT logs |
| GET | `/admin/bloom-filter/whitelist` | Download whitelist bloom filter (binary) |
| GET | `/admin/bloom-filter/blacklist` | Download blacklist bloom filter (binary) |
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
| `domain_heuristics` | String analysis: length, hyphens, digits, TLD risk, subdomain depth, entropy | Pure computation |
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

Two separate bloom filters, both using **base domains only** (subdomains stripped):

- **Whitelist bloom**: known-safe base domains. On-device: match -> silent allow.
- **Blacklist bloom**: known-bad base domains. On-device: match -> instant block.

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
3. Deduplicate across all sources
4. Skip domains already in DynamoDB (blacklist, whitelist, or cache)
5. Batch insert new domains as `entry_type=blacklist`

**Whitelist auto-discovery**: Certificate Transparency logs via `crt.sh`. Given a root domain (e.g., `brou.com.uy`), discovers all subdomains from CT logs and adds them as whitelist entries with a partner_id. Wildcards (`*.domain`) are excluded.

### Scheduler

APScheduler runs a daily job at 03:00 UTC:

1. Ingest all public blacklist feeds
2. Regenerate both bloom filters and write to disk

On startup, the same ingestion + bloom generation runs as a background task (non-blocking).

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
5. Layer 1: Check runtime blacklist -> NOT FOUND (first time seeing this domain)
   |
6. Layer 2: Check bloom whitelist for base domain "brou-seguro.com" -> NOT FOUND
   |
7. Layer 3: Check bloom blacklist for base domain "brou-seguro.com" -> FOUND
   |  (brou-seguro.com was ingested from PhishTank/OpenPhish and is in the
   |   blacklist bloom filter)
   |
8. BLOCKED:
   a. DNS response: brou-seguro.com -> 127.0.0.1
   b. Browser requests HTTP to 127.0.0.1
   c. Block page server returns Spanish "Sitio bloqueado" HTML page
   d. BlockLog.append() records the event (red severity)
   e. Push notification: "Phishing link blocked"
   f. User sees block page in browser + notification banner
```

If the domain is NOT in the bloom blacklist but is similar to a whitelisted domain (e.g., `br0u.com.uy` with a zero instead of 'o'):

```
1-6. Same as above, bloom filters don't match
   |
7. Layer 4: DomainChecker.check()
   a. Not in hardcoded blacklist
   b. Not in hardcoded whitelist
   c. BK-tree search: "br0u.com.uy" vs "brou.com.uy" -> distance 1, similarity 90%
   d. Result: WARN
   |
8. Layer 5: Hold DNS, call POST /check with domain "br0u.com.uy"
   |
9. Backend: not in DynamoDB -> run LangGraph agent
   a. Agent calls domain_heuristics: "Contains brand name: brou"
   b. Agent calls levenshtein_similarity: "brou.com.uy: distance=1, similarity=91%"
   c. Agent calls dns_lookup: "Domain registered 3 days ago (very new)"
   d. Agent calls ssl_certificate_check: "Free CA (Let's Encrypt), cert 2 days old"
   e. Agent verdict: {"verdict": "block", "confidence": 0.95, "reasoning": "..."}
   |
10. Backend caches result in DynamoDB (TTL 30 days)
    |
11. iOS receives "block" verdict:
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

1. **Bloom filter downloads** (startup + daily): the app fetches two binary bloom filter files from the backend. These are generic filter files, not user-specific. No user data is sent.

2. **Domain checks** (Layer 5 only): a domain name is sent to the backend ONLY when the on-device heuristics produce a WARN verdict (Levenshtein similarity to a known official domain). This represents a small fraction of all DNS queries. The request contains only the domain name -- no user identifier, no URL path, no page content, no browsing history.

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

131 unit tests across 5 test files, all using pytest with async support.

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
|   |   +-- DomainChecker.swift      # 5-layer domain check logic
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
+-- README.md
+-- architecture.md                  # This file
```

# Architecture diagram

Quick-glance system view. Read this first, then dive into
[../architecture.md](../architecture.md) for full detail (~900 lines).

The system has four parts:

1. **iOS app** — SwiftUI app + NetworkExtension packet tunnel doing DNS
   interception. On-device pipeline of 10 layers. The vast majority of DNS
   queries (~98%) never touch the network.
2. **Backend API** — FastAPI on AWS Fargate. Handles `/check` (per-domain
   verdict), `/daily-blacklist`, bloom-filter serving, and admin endpoints.
3. **LangGraph investigation agent** — backend-internal. Runs only for
   uncertain domains. Bedrock Claude Sonnet driving a tool-using loop.
4. **Ingestion + ML pipelines** — backend-internal scheduled jobs that build
   bloom filters from public threat feeds and ship an on-device ML model.

---

## High-level

```mermaid
graph LR
  subgraph Device["iOS Device"]
    App["24Defend App<br/>(SwiftUI)"]
    Tunnel["PacketTunnelProvider<br/>(DNS intercept,<br/>10-layer check)"]
    App <-->|App Group<br/>UserDefaults| Tunnel
  end

  Tunnel -->|"DNS (UDP/53)<br/>only for blocked"| Sinkhole["127.0.0.1<br/>block page"]
  Tunnel -->|"DNS (UDP/53)<br/>uncertain or<br/>~0.2% of queries"| Upstream["Upstream DNS<br/>(1.1.1.1)"]

  Tunnel -->|"HTTPS /check<br/>(only for uncertain)"| API["Backend API<br/>(FastAPI, Fargate)"]
  Tunnel -->|"HTTPS /daily-blacklist<br/>/daily-false-positives<br/>(every 30 min)"| API
  Tunnel -->|"HTTPS bloom filters<br/>(at startup, every 24h)"| CDN["S3 + CloudFront"]

  API --> DDB[("DynamoDB<br/>domains, verdicts,<br/>agent cache")]
  API --> Bedrock["AWS Bedrock<br/>Claude Sonnet"]
  API --> S3["S3<br/>bloom filters,<br/>ML model"]
  S3 --> CDN

  Ingest["Scheduled ingestion<br/>(03:00 UTC daily)"] --> Feeds["PhishTank, URLhaus,<br/>OpenPhish, Phishing.Army,<br/>Majestic Million"]
  Ingest --> DDB
  Ingest --> S3
```

**Key property**: the device only contacts the backend for domains that
weren't conclusively handled by the on-device layers. Cache hit rate is
~98.2% — most DNS queries never leave the device.

---

## On-device detection pipeline (10 layers)

Each DNS query runs through these in order. First match wins. See
[../architecture.md](../architecture.md) section "10+ Layer Check Order" for
the full per-layer behavior.

```mermaid
flowchart TD
  Q["DNS query<br/>(domain)"] --> L0
  L0["L0: Verdict cache<br/>LRU 2K, 1h TTL"]
  L0 -->|hit| Verdict([cached verdict])
  L0 -->|miss| L1["L1: Runtime blacklist<br/>(session-only)"]
  L1 -->|hit| Block([BLOCK])
  L1 -->|miss| L2["L2: Infrastructure allowlist<br/>(CDN, ad-tech, Google,<br/>Apple, Cloudflare...)"]
  L2 -->|hit| Allow([ALLOW silently])
  L2 -->|miss| L3["L3: Bloom whitelist<br/>(known-safe base domains)"]
  L3 -->|hit| Allow
  L3 -->|miss| L4["L4: Dual bloom blacklist<br/>(A AND B must match;<br/>FP rate ~1 in 670K)"]
  L4 -->|both hit| L4FP{In local FP list?}
  L4FP -->|yes| Allow
  L4FP -->|no| API1["Confirm with backend<br/>POST /check (~50ms)"]
  API1 -->|block| Block
  API1 -->|allow| AllowFP([ALLOW + record FP])
  L4 -->|miss| L4b["L4b: Daily blacklist<br/>(polled every 30 min)"]
  L4b -->|hit| Block
  L4b -->|miss| L5["L5: BK-tree Levenshtein<br/>(typosquat detection<br/>vs whitelist)"]
  L5 -->|warn| API2["Backend /check"]
  L5 -->|miss| L6["L6: Brand rule engine<br/>(UY brands + Spanish<br/>phishing vocab + TLD risk)"]
  L6 -->|score >= 0.7| API2
  L6 -->|miss| L7["L7: ML classifier<br/>(20 features, 1 KB model,<br/>SILENT)"]
  L7 -->|score >= 0.5| Background["Submit to /check<br/>in background<br/>(PendingInvestigation)"]
  L7 -->|low score| L8[ALLOW]
  API2 -->|block| Block
  API2 -->|allow/unreachable| Warn([WARN to user])
  Background -.->|"poll every 30s,<br/>up to 10 min"| RetroNotif["Retroactive<br/>notification if<br/>agent says<br/>should_notify=true"]
```

**Important**: Layer 7 (ML) never produces a user-facing warning. Only
Layers 5 and 6 do. Layer 4 always confirms with the backend before
blocking; bloom filter alone is never enough.

---

## Backend agent flow (LangGraph)

Only runs when `/check` is called on a domain not in DynamoDB. Loops
LLM → tools → LLM until the LLM returns a final JSON verdict.

```mermaid
graph TD
  Check["POST /check"] --> Lookup{Domain in<br/>DynamoDB?}
  Lookup -->|"blacklist"| RetBlock([verdict=block<br/>should_notify=true])
  Lookup -->|"whitelist"| RetAllow([verdict=allow])
  Lookup -->|"cache (fresh)"| RetCached([cached verdict])
  Lookup -->|"miss or stale"| Agent["LangGraph agent<br/>(Bedrock Claude Sonnet,<br/>temperature 0)"]

  Agent --> Decide{LLM asks<br/>for tools?}
  Decide -->|yes| Tools["Run tool(s)"]
  Tools --> Agent
  Decide -->|no| Parse["Parse JSON verdict<br/>verdict / confidence /<br/>should_notify / reasoning"]
  Parse --> Cache["Write to DynamoDB<br/>(cache, 30d TTL;<br/>7d if unclear, 1h if failed)"]
  Cache --> Resp([HTTP response])

  Tools --> T1[domain_heuristics<br/>pure computation]
  Tools --> T2[levenshtein_similarity<br/>vs whitelist]
  Tools --> T3[dns_lookup / RDAP<br/>domain age]
  Tools --> T4[ssl_certificate_check<br/>direct TLS]
  Tools --> T5[google_search<br/>Serper API]
  Tools --> T6[safe_browsing_check<br/>Lookup API v4]
```

`should_notify` is **agent-owned**: the iOS app trusts the boolean in the
response. The agent only sets it true under strict criteria (confidence ≥
0.85, identifiable brand impersonation, multiple converging signals).
Blacklist hits always set `should_notify=true`. See
[../CLAUDE.md](../CLAUDE.md) "Pending investigations (retroactive
warnings)".

---

## Data flow: ingestion → device

How the daily blacklist and bloom filters get from public threat feeds to a
user's phone.

```
+-------------------------------+
| Public threat feeds           |
|  - OpenPhish (continuous)     |
|  - PhishTank (hourly)         |
|  - URLhaus (5 min)            |
|  - Phishing.Army (daily)      |
+---------------+---------------+
                |
                | concurrent fetch
                v
+-------------------------------+
| Backend ingestion (03:00 UTC) |
|  1. Fetch + parse all feeds   |
|  2. Extract base domains      |
|  3. Filter via Majestic       |
|     Million top 100K          |
|     (skip shared infra)       |
|  4. Dedupe                    |
|  5. Skip domains already in   |
|     DynamoDB                  |
|  6. Batch insert (entry_type= |
|     blacklist) to DynamoDB    |
+---------------+---------------+
                |
                v
+-------------------------------+
| Bloom filter generation       |
|  - Whitelist bloom            |
|  - Blacklist bloom A          |
|  - Blacklist bloom B          |
|  (MurmurHash3, signed mod,    |
|   binary [m][k][bits])        |
+---------------+---------------+
                |
                v
+-------------------------------+
| S3 + CloudFront               |
+---------------+---------------+
                |
                | iOS pulls every 24h
                v
+-------------------------------+
| iOS BloomFilterStore          |
|  (App Group UserDefaults)     |
+-------------------------------+

Separate path, polled every 30 min:
  /daily-blacklist          - confirmed-bad in last 48h
  /daily-false-positives    - confirmed-good bloom FPs in last 48h
```

---

## Where to go next

| If you want to understand…                  | Read                                                     |
|---------------------------------------------|----------------------------------------------------------|
| iOS DNS interception internals              | [../architecture.md](../architecture.md) "PacketTunnelProvider DNS Interception Flow" |
| Exact per-layer logic                       | [../architecture.md](../architecture.md) "10+ Layer Check Order" |
| Agent prompt and tool semantics             | `backend/app/investigation/graph.py`, `tools.py`         |
| Bloom filter binary format / signed modulo  | [../architecture.md](../architecture.md) "BloomFilter Binary Format", [../CLAUDE.md](../CLAUDE.md) "Signed modulo" |
| What gets ingested and how it's filtered    | [../architecture.md](../architecture.md) "Ingestion"     |
| ML feature list and training                | [../architecture.md](../architecture.md) "ML Pipeline"   |
| Why each component looks like this          | [../CHANGELOG.md](../CHANGELOG.md) (chronological)       |
| Common failures and fixes                   | [troubleshooting.md](troubleshooting.md)                  |

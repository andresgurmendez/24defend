# 24Defend — Planned Improvements

Backlog of improvements identified during MVP development and real-device testing.
Prioritized by impact on user experience and detection quality.

---

## 1. Block page for HTTPS sites

**Problem**: DNS-level blocking returns 127.0.0.1, but Safari tries HTTPS first. Without a valid
SSL cert for the blocked domain, the user sees "Safari Can't Connect" instead of our branded
block page. The notification works but isn't as visible as an in-browser page.

**Options explored**:

| Approach | Feasibility | Notes |
|----------|------------|-------|
| HTTP block page (current) | Works for HTTP-only sites | ~10% of phishing sites |
| HTTPS reject listener on 443 | Partial | Forces Safari fallback to HTTP sometimes |
| Custom URL scheme redirect | Unlikely | HTTPS handshake fails before redirect |
| Safari Content Blocker extension | Possible | Safari-only, doesn't cover other apps |
| Apple NetworkExtension block page API | Not available | May come in future iOS versions |
| Notification + in-app detail screen | Current solution | Works 100% of the time |

**Recommendation**: Invest in making the notification experience excellent rather than fighting
the HTTPS limitation. Add actionable buttons to the notification (e.g., "View Details",
"Report False Positive"). Consider a Safari Web Extension that detects blocked domains and
shows an interstitial — this would only work in Safari but covers the primary use case.

**Future**: If Apple introduces a block page API for NEPacketTunnelProvider, adopt it immediately.
Monitor WWDC annually for NetworkExtension updates.

---

## 2. False positive handling

**Problem**: Bloom filter FP rate is ~0.1% (1 in 1000 random domains). Combined with 72K entries,
this means ~72 random domains could falsely match. Infrastructure allowlist catches most, but
edge cases will appear (e.g., `googleapis.com` was blocked as a bloom filter FP).

### 2a. User-facing false positive reporting

Allow users to report "this site was wrongly blocked" directly from the notification or block
detail screen.

**Flow**:
1. User gets blocked notification for a legitimate site
2. Taps "Report false positive" button
3. App sends `POST /report/false-positive` with domain + device context
4. Backend stores the report
5. If N users report the same domain → auto-add to infrastructure allowlist
6. Manual review queue for ambiguous cases

**Implementation**:
- Add "Not phishing?" button to the block notification (UNNotificationAction)
- Add report endpoint to backend
- DynamoDB table for reports: domain, user_count, first_seen, last_seen
- Threshold: 3+ reports for same domain → auto-allowlist
- Daily review of reports for patterns (are attackers gaming the report system?)

### 2b. Multi-layer confirmation before blocking

Instead of blocking on a single bloom filter hit, require confirmation from a second source:

```
Bloom filter hit → check against backend /check endpoint → if blacklist confirmed → block
                                                         → if not in backend → allow (FP)
```

This eliminates bloom filter FPs entirely at the cost of one API call per bloom hit.
The API call is fast (~50ms) because it's a DynamoDB lookup, not an agent investigation.

**Trade-off**: adds 50ms latency to all bloom-filter-blocked domains, but eliminates FPs completely.
Could be opt-in: "strict mode" blocks on bloom filter alone, "safe mode" confirms with backend.

### 2c. Infrastructure allowlist improvements

- Expand the allowlist with Tranco top 10K base domains (auto-downloaded monthly)
- Add regional domains: `.gub.uy`, UY government sites, UY news sites, UY banks (already whitelisted)
- Ship the allowlist as a separate bloom filter from the backend (updatable without app release)

---

## 3. Chained / layered bloom filters

**Problem**: A single large bloom filter (72K entries, 127 KB) has a fixed FP rate. Making it
bigger reduces FPs but increases download size and memory.

**Alternative: chained bloom filters**

```
Bloom 1 (coarse, small, low FP)  → if miss → allow
                                  → if hit → check Bloom 2

Bloom 2 (fine, larger, very low FP) → if miss → allow (was Bloom 1 FP)
                                     → if hit → block (confirmed)
```

Two smaller bloom filters in series: the first is fast but has higher FP rate. The second only
runs on hits from the first, so it can be larger without affecting most queries. Combined FP rate
is the product of the two rates: 0.1% x 0.1% = 0.0001%.

**Implementation**: backend generates two bloom filters with different hash seeds. Device downloads
both. Check order: Bloom1 → Bloom2 → block. Cost: ~2x download size but ~1000x lower FP rate.

**Alternative structures**:

| Structure | FP rate | Size | Lookup time | Notes |
|-----------|---------|------|------------|-------|
| Bloom filter (current) | 0.1% | 127 KB | O(k) | Simple, proven |
| Chained bloom (2-layer) | 0.0001% | ~250 KB | O(2k) | Eliminates FPs practically |
| Cuckoo filter | 0.001% | ~100 KB | O(1) | Supports deletion, slightly complex |
| Counting bloom filter | 0.1% | ~500 KB | O(k) | Supports deletion, larger |
| Xor filter | 0.001% | ~80 KB | O(3) | Smallest, immutable, newest |
| Ribbon filter | 0.001% | ~75 KB | O(1) | Smallest theoretical, complex |

**Recommendation**: Xor filter or chained bloom filter. Xor filters are ~40% smaller than bloom
filters for the same FP rate, and lookup is exactly 3 hash computations. The downside is they're
immutable (rebuild from scratch on update) — fine for our use case since we regenerate daily.

---

## 4. Device telemetry / event reporting

**Problem**: We have no visibility into what the app is actually doing on real devices.
How many domains are checked? How many blocked? What's the cache hit rate? Are there FPs
we don't know about?

### 4a. Event reporting to backend

Report anonymized detection events to the backend for analysis.

**Events to report**:

| Event | Data | Frequency |
|-------|------|-----------|
| `domain_blocked` | base_domain, layer (bloom/brand/ML/agent), verdict | Every block |
| `domain_warned` | base_domain, layer, verdict | Every warning |
| `false_positive_report` | domain, user_report | User-initiated |
| `bloom_refresh` | whitelist_size, blacklist_size, download_ms | On refresh |
| `classifier_refresh` | model_version, download_ms | On refresh |
| `session_stats` | total_queries, cache_hits, bloom_hits, api_calls, blocks, warns | Hourly aggregate |

**Privacy considerations**:
- Send base domains only (not full URLs or subdomains)
- Don't send allowed domains — only blocks/warns (user isn't tracked)
- Aggregate session stats (not per-query reporting)
- No user identifier beyond a random device token (not tied to Apple ID)
- Privacy policy must disclose: "blocked domain names are reported to improve detection"
- Opt-out setting in app (reduces detection quality but respects user choice)

**Implementation**:
- `POST /telemetry/events` endpoint (batch, async, fire-and-forget)
- DynamoDB table: `24defend-events` with TTL (90-day retention)
- Daily aggregation job: compute top blocked domains, FP rate, layer distribution
- Dashboard: "24Defend by the numbers" for institutional partners

### 4b. Stats dashboard in the app

Show the user their own protection stats:

```
Protected for 14 days
12,847 DNS queries checked
23 threats blocked
0 suspicious warnings
Last bloom filter update: 2 hours ago
```

Builds trust and engagement. Data comes from local counters (no network needed).

### 4c. Institutional dashboard (web)

Show partner institutions:

```
BROU Dashboard — April 2026
Phishing domains targeting BROU: 47 this month
Domains blocked for BROU customers: 1,234
New domains detected: 12 (3 confirmed, 9 investigating)
Top attack pattern: "brou-actualizacion" variants
```

Data sourced from telemetry events filtered by brand keyword match.

---

## 5. Active learning pipeline

**Problem**: The ML classifier was trained on synthetic data. Real-world phishing patterns differ.
Need real data to improve the model.

**Pipeline**:

```
Device traffic → 1% random sample of unknown domains
  → POST /telemetry/sample (domain only, no user context)
  → Backend agent investigates
  → Verdict becomes training label
  → Monthly: retrain model on real + synthetic data
  → Ship updated weights via CDN
  → Devices download on next refresh
```

**Sampling strategy**:
- Only sample domains NOT in cache, bloom filters, or infrastructure allowlist
- Exclude Tranco top 100K (known legitimate, not useful for training)
- Sample rate: 1% initially, adjustable per-region
- Cap: max 10 samples per device per day (battery/bandwidth)

**Privacy**: Only the domain name is sent. No browsing context, no user ID.
The domain is already being resolved via DNS — we're not adding new data exposure.

---

## 6. Notification improvements

### 6a. Actionable notification buttons

```
[Phishing link blocked]
brou-seguro.xyz is a known malicious site.

[View Details]  [Not phishing?]  [Share]
```

- "View Details" → opens app to block detail screen (already implemented)
- "Not phishing?" → reports false positive (new)
- "Share" → WhatsApp share with pre-written message (viral loop from the doc)

### 6b. Share button (viral growth)

From the block detail screen or notification:

```
"24Defend just blocked a phishing link impersonating [BRAND]. 
Download the free app to protect yourself: https://24defend.com/download"
```

The doc identifies this as the #1 growth mechanism. Each block event is a potential
viral share to 30+ people in a WhatsApp group.

### 6c. Notification grouping

Current bug: same domain triggers multiple notifications (DNS retries).
Fix: notification ID based on domain, not UUID. iOS auto-groups by ID.
Already partially implemented with debounce Set, but the cache + debounce
interaction needs review.

---

## 7. Battery and performance

### 7a. DNS query batching

Currently each DNS packet is processed individually. Could batch packets received within
a 10ms window and process together — reduces context switches.

### 7b. Bloom filter memory mapping

Current: load entire bloom filter into memory (127 KB blacklist).
Could: memory-map the file for larger bloom filters (>1 MB) to reduce RSS.
Not needed at current scale but relevant if bloom filter grows to millions of entries.

### 7c. Background refresh timing

Current: 24-hour timer fires regardless of network state.
Improvement: use iOS Background Task API to schedule refreshes during charging + WiFi,
reducing cellular data usage and battery impact.

---

## 8. Model improvements

### 8a. Train on real data

Once the active learning pipeline (section 5) collects ~10K real domain samples,
retrain the logistic regression and compare against synthetic-only model.
Expected improvement: fewer FPs on infrastructure domains, better recall on
novel LatAm phishing patterns.

### 8b. Gradient boosted model on backend

Use the GBM model (238 KB, AUC 0.9999) on the backend for agent pre-screening.
Before running the full LangGraph agent (25s, $0.005), run GBM first (<1ms).
If GBM says "allow" with >0.95 confidence, skip the agent entirely.
Reduces agent invocations by ~60%.

### 8c. Feature engineering

New features from real-world false positive analysis:
- `is_cdn_pattern`: domain matches CDN naming patterns (hex strings, edge nodes)
- `is_load_balancer`: domain matches LB patterns (e.g., `elb.amazonaws.com`)
- `subdomain_is_hex`: subdomain is hexadecimal string (CDN, not phishing)
- `registered_brand_tld`: domain is brand.{official_tld} (e.g., santander-mx.com is legit Santander Mexico)

---

## 9. Regional expansion

### 9a. Country-specific brand lists

When expanding beyond Uruguay:
- Chile: BancoEstado, BCI, Banco de Chile, Falabella, CMR
- Argentina: Banco Nacion, Galicia, BBVA Argentina, Mercado Pago AR
- Colombia: Bancolombia, Davivienda, Banco de Bogota
- Brazil: Banco do Brasil, Bradesco, Nubank, Pix-related domains
- Mexico: BBVA Mexico, Banorte, Santander Mexico, Banco Azteca

Each country needs its own brand keyword list and phishing vocabulary
(e.g., Brazil uses Portuguese, not Spanish).

### 9b. santander-mx.com type domains

Current bug: `santander-mx.com` is flagged because it contains "santander" brand keyword.
But this is Santander Mexico's legitimate domain. Need a way to distinguish:
- `santander-mx.com` (legitimate, Santander Mexico) vs
- `santander-verificacion.com` (phishing)

Fix: expand the whitelist to include legitimate international variants of partner brands.
Or: only flag if brand + phishing_word, not brand alone.

---

## Priority order

1. **False positive reporting** (2a) — users need a way to tell us when we're wrong
2. **Device telemetry** (4a) — we're flying blind without data from real devices
3. **Notification buttons** (6a) — "Not phishing?" + "Share" are high-impact UX
4. **Infrastructure allowlist expansion** (2c) — Tranco top 10K prevents most FPs
5. **Chained bloom filters or xor filter** (3) — eliminates bloom FPs structurally
6. **Active learning pipeline** (5) — real data improves the model
7. **In-app stats** (4b) — builds user trust and engagement
8. **Share viral loop** (6b) — growth mechanism from the doc
9. **Regional expansion** (9) — after UY is stable

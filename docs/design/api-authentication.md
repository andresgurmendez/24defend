# API Authentication & Anti-Abuse — Design & Plan

**Status:** proposed, pending implementation
**Owner:** Uriel (developer)
**Reviewer:** Maximo
**Target:** production before public App Store launch (mid-September 2026)
**Implementation window:** 11/08 – 22/08 (two weeks)
**Stabilization + App Store prep:** 25/08 – 12/09

---

## 1. Problem

Today `api.24defend.com` is a fully public HTTP endpoint. Any client can call
`/check`, `/bloom-filter/*`, `/daily-blacklist`, `/daily-false-positives`, and
`/telemetry/events` without authentication.

Because the iOS app has **no user account** (this is a differentiator we
intentionally preserve — see `www.24defend.com` positioning), we cannot gate
access via user credentials. Any static secret embedded in the app can be
reverse-engineered out of the IPA in minutes.

Concrete consequences at scale:

- **`/check` invokes Bedrock** at roughly $0.05 per fresh investigation.
  A modest bot doing 20 requests/second sustained = ~$86/day in LLM cost with
  zero user benefit.
- **`GET /bloom-filter/*`** and **`GET /daily-blacklist`** are pure
  threat-intelligence data. A competitor can build a lookalike product by
  polling these endpoints on schedule.
- **`POST /telemetry/events`** accepts arbitrary counters. Poisoned events
  distort internal metrics and any "protection quality" numbers we later
  report externally.
- **Volumetric abuse / DDoS** — unmitigated.

This must be resolved before we publish the app on the App Store. Once
listed, `api.24defend.com` becomes trivially discoverable via anyone
inspecting the app's network traffic on a proxy.

## 2. Threat model

**In scope**

1. Bedrock cost abuse via `/check` — bots calling with random domains or
   targeted phishing candidates to burn our LLM bill.
2. Threat-feed exfiltration — scraping `GET /bloom-filter/*` and
   `/daily-blacklist` on a schedule to replicate our data.
3. Telemetry poisoning — malformed events that skew our internal metrics
   or reporting.
4. Volumetric / naïve DDoS — flooding endpoints from cheap infrastructure.
5. Static-secret extraction — anyone reverse-engineering the app who finds a
   hardcoded token can call the API forever without any rotation cost.

**Out of scope**

- A jailbroken device controlled by a real user of the app. They can use
  the app normally; we cannot reliably distinguish them from a normal user
  beyond what Apple already provides. Not a meaningful attack surface.
- Nation-state adversaries with unlimited resources. Not the profile for
  a consumer anti-phishing app.

## 3. Non-goals

- **Per-user identification.** We do not have accounts. We do not want them.
  This design must preserve that.
- **Per-user quotas or personalization.** We do not know who a "user" is —
  only which device.
- **Cross-platform coverage.** We ship iOS only. The design should not fight
  a future Android port (Play Integrity API applies the same shape), but the
  initial implementation is iOS-only.
- **Web browser access.** If we ever want a public "paste a URL to check it"
  page, it lives as a separate service with its own bot protection
  (Cloudflare Turnstile or equivalent). Not this design.

## 4. Proposed architecture

Three complementary layers, cheapest first, each independently useful:

```
Client (iOS)                     AWS edge                         Backend
────────────                     ────────                         ───────
  DeviceAuth.sign(request)  →   [WAF: rate-limit, common rules]  →  [require_device_auth]
                                 [Shield Standard: DDoS filter]      [FastAPI route]
                                                                     [Rate limit / device]
                                                                     [Application]
```

### Layer 1 — Network edge: AWS WAF on the ALB

Attach an AWS WAF Web ACL directly to the existing ALB fronting
`api.24defend.com`. Managed via CDK in `infra/stack.py`.

Rules:

- **`AWSManagedRulesCommonRuleSet`** — SQL injection, XSS, protocol
  violations, request size limits. Free within the rule group.
- **Rate-based rule** — 100 requests per 5-minute rolling window per source
  IP. Blocks the naïve bot with a single IP address.
- **Log every allowed and blocked request** to CloudWatch with the matching
  rule name, so we can see attack shapes post-hoc.

Shield Standard is enabled by default at the AWS account level. Free.

Cost estimate: ~$15/mo (Web ACL $5 + 2 rules $2 + traffic $0.60 per million
requests, at our current volume of low thousands per day).

**Later upgrade path:** if bandwidth cost from bulk downloads becomes
visible, put **CloudFront** in front of the ALB and cache
`GET /bloom-filter/*` at LATAM edge locations. Defer unless traffic
justifies it — probably around 10k+ active users.

### Layer 2 — Device attestation: Apple App Attest bootstrap

On first launch, the iOS app:

1. Generates a keypair inside the **Secure Enclave** via
   `DCAppAttestService.generateKey()`. The private key cannot be extracted,
   even from a jailbroken device.
2. Requests a fresh nonce from `POST /auth/challenge`.
3. Requests an attestation from Apple:
   `DCAppAttestService.attestKey(keyId, hash(nonce))`.
4. Sends the resulting attestation object to `POST /auth/register`.

The backend verifies the attestation against Apple's servers, confirming:

- The app is genuinely our app (bundle ID `com.24defend.app`, Team ID
  matches `332CN243S9`).
- The device is real iOS hardware (not simulator, not modified).
- The key is genuinely rooted in the Secure Enclave.

On successful verification, the backend stores
`(deviceId, publicKey, keyId, bundleId, teamId, attestedAt, assertionCounter)`
in a new DynamoDB table `24defend-devices` (defined in CDK) and returns the
`deviceId` (opaque hash) to the app.

**Failure modes:**

- Attestation invalid (bundle ID mismatch, Team ID mismatch, expired
  receipt) → HTTP 401, app treats as fatal and shows "cannot activate
  protection" error.
- Attestation valid but network error mid-request → app retries with
  exponential backoff. Bootstrap is idempotent — re-registering the same
  keyId returns the same deviceId.

### Layer 3 — Per-request signing

Every subsequent authenticated API call is signed by the Secure Enclave key:

1. Client constructs the client data:
   ```
   {
     "method": "POST",
     "path": "/check",
     "bodyHash": "<sha256 of body>",
     "timestamp": "2026-08-15T14:23:11Z",
     "deviceId": "<deviceId>"
   }
   ```
2. Client calls `DCAppAttestService.generateAssertion(keyId, hash(clientData))`.
3. Client sends the request with three headers:
   - `X-Defend-Device-Id: <deviceId>`
   - `X-Defend-Assertion: <base64(assertion)>`
   - `X-Defend-Timestamp: <ISO8601>`

Backend middleware `require_device_auth`:

1. Rejects with 401 if timestamp skew exceeds ±5 minutes (prevents replay
   after long delay).
2. Loads `publicKey`, `assertionCounter`, `revoked` for `deviceId` from DDB.
   In-memory cache with 15-min TTL to avoid a DDB read on every request.
3. Rejects with 403 if `revoked == true`.
4. Rebuilds clientData from the request headers + body.
5. Verifies the assertion against `publicKey` using Apple's counter-based
   scheme. New counter must be strictly greater than the stored value; if
   accepted, updates the stored value atomically (DDB conditional update).
6. Enforces per-device rate limit (see section 6).
7. Passes the request to the route handler.

Per-request overhead: ~50 ms client-side (`generateAssertion` in Secure
Enclave) + ~10 ms server-side (verification). Negligible at our scale and
for our latency budget.

## 5. Endpoint policy

| Endpoint | Layer 1 WAF | Layer 2/3 Device Auth | Notes |
|---|---|---|---|
| `GET /health` | Yes | No | ALB health check must not require auth. |
| `POST /auth/challenge` | Yes | No | Chicken-and-egg — needed before registration. |
| `POST /auth/register` | Yes | No (self-verifying via Apple) | The attestation IS the proof. |
| `POST /check` | Yes | Yes | High-cost endpoint, must be gated. |
| `GET /bloom-filter/*` | Yes | Yes | Bulk threat intel. Must gate to prevent scraping. |
| `GET /daily-blacklist` | Yes | Yes | Same rationale as bloom filter. |
| `GET /daily-false-positives` | Yes | Yes | Same. |
| `POST /telemetry/events` | Yes | Yes | Prevents poisoning. |
| `/admin/*` | Yes | No — uses existing `X-Admin-Token` | Service-to-service, out of scope. |

## 6. Rate limits (per-device, backend-enforced)

Applied AFTER Layer 3 verification. MVP implementation: in-memory
sliding-window counter in each FastAPI worker (state is lost on restart —
acceptable, since a restart-driven reset is a much smaller attack surface
than the unauthenticated baseline). Later can migrate to DDB atomic counters
if we ever run multiple workers or need cross-restart persistence.

| Endpoint | Limit | Rationale |
|---|---|---|
| `POST /check` | 100 req/min per device | p99 real user is ~20 req/min. 5× headroom. |
| `GET /bloom-filter/*` | 4 req/day per device | Matches the 24-hour refresh cadence. Anything more is a scrape. |
| `GET /daily-blacklist` | 50 req/day per device | Matches 30-min refresh + tunnel restart re-fetches. |
| `POST /telemetry/events` | 30 req/hour per device | Real usage is ~1 req/hour. Anything more is telemetry spam. |
| `POST /auth/challenge` | 5 req/hour per **source IP** | Prevents challenge exhaustion pre-registration. |
| `POST /auth/register` | 3 req/day per **source IP** | Registration should be a rare per-install event. |

Exceeding a limit returns HTTP 429 with `Retry-After` header. Logged to
CloudWatch as `RATE_LIMIT_EXCEEDED deviceId=... endpoint=...` for post-hoc
analysis.

## 7. Data model

**New DynamoDB table `24defend-devices`** (add to `infra/stack.py`):

| Field | Type | Description |
|---|---|---|
| `deviceId` | String (partition key) | SHA-256(`keyId` + `bundleId` + `teamId`), truncated to 32 chars. Opaque, not derivable from install data. |
| `publicKey` | String (base64) | Secure Enclave public key from the attestation. |
| `keyId` | String (base64) | Apple's key identifier. Needed for revocation via Apple's server. |
| `bundleId` | String | Must equal `com.24defend.app`. |
| `teamId` | String | Must equal our Team ID (`332CN243S9`). |
| `attestedAt` | ISO timestamp | When the device first registered. |
| `lastSeenAt` | ISO timestamp | Updated per authenticated request, throttled to once per hour to reduce DDB write cost. |
| `assertionCounter` | Number | Monotonically increasing per Apple's assertion protocol. Prevents replay attacks. |
| `revoked` | Boolean | Set to true to reject all future requests. |
| `revokedReason` | String (optional) | Free-form audit trail — why did we revoke. |

No TTL. Devices live forever unless explicitly revoked.

Cost: ~200 bytes per device × 100k users = 20 MB storage + occasional
reads/writes. Well below the DDB free tier.

## 8. Fallback: unsupported environments

`DCAppAttestService.isSupported == false` on:

- **iOS Simulator** (Xcode)
- **Xcode direct-install** to development-provisioned devices
- Enterprise-provisioned apps (irrelevant for us)

Handling:

- **Debug builds** (`#if DEBUG`) — bypass. Sign with a static dev-mode token
  (from `.env.local`) that the backend accepts only when
  `settings.environment == "dev"`.
- **TestFlight / App Store builds** on unsupported devices — hard fail with
  a clear message: *"Este dispositivo no puede activar 24Defend. Contactá
  con contacto@24defend.com"*. Also log to `DiagnosticLog` so the tester can
  send us the log via the 7-tap panel.

Our `project.yml` sets `deploymentTarget: iOS 16.0`. App Attest requires
iOS 14+. Every device that can install the app supports App Attest by
definition. No legitimate user on real hardware will hit the fallback.

## 9. Revocation

If a device is misbehaving (extracted key, spam pattern, etc.):

1. Manually set `revoked = true` on its DDB row via an admin endpoint or CLI.
2. Middleware short-circuits every subsequent request from that `deviceId`
   with HTTP 403 and header `X-Defend-Revoked: true`.
3. Client-side: on receiving `X-Defend-Revoked: true`, show a modal
   *"La protección fue desactivada. Contactá con soporte."* and disable
   the VPN. Log to `DiagnosticLog`.
4. Optional Phase 2: call Apple's revocation API to invalidate the key at
   Apple's level.

Manual admin CLI is fine for MVP. A dashboard for revocation lives in a
future admin UI (documented in `issues.md`).

## 10. Observability

Every layer emits structured logs to CloudWatch:

- **WAF** — rule matches (allowed / blocked), source IP, path, User-Agent.
- **`POST /auth/register`** — success + failure reason (bundle ID mismatch,
  invalid attestation, etc.).
- **`require_device_auth` middleware** — pass, fail with reason (bad
  timestamp, counter regression, unknown device, revoked).
- **Rate limits** — every 429.
- **Revocation** — every manual `revoked = true` action, with actor.

Dashboards to build in CloudWatch (backlog after implementation):

- Attestations per hour — bootstrap health signal.
- Auth failures per hour — attack indicator (should be near zero in
  steady state).
- Rate-limit rejections broken down by endpoint and by deviceId.
- Registered devices — business metric (roughly proportional to
  installed base).

## 11. App Store submission considerations

Before mid-September launch, three consistency artifacts must agree:

**1. Privacy Manifest — `PrivacyInfo.xcprivacy`**

The Keychain-related required-reason code `CA92.1` is already declared.
`DCAppAttestService` itself does not require an additional reason code.
Verify with `plutil -p` on the built manifest that no new required-reason
API is missing.

**2. App Privacy questionnaire — App Store Connect**

Add **Device ID** data type. Declaration: "Not Linked to User, Not Used
for Tracking, Purpose: App Functionality." Existing declarations (Product
Interaction, Other Data Types) unchanged.

**3. Privacy policy — `www/privacy-es.html`**

Add one sentence:

> Al activar la aplicación se genera un identificador anónimo del dispositivo
> que se registra en nuestros servidores para autenticar las consultas de la
> app. Este identificador no está vinculado a ningún dato personal tuyo y no
> se comparte con terceros.

**4. App Store Review notes**

Add to the existing notes about the diagnostic panel:

> On first launch, the app performs a one-time device attestation with
> Apple's App Attest service to authenticate subsequent API calls. No user
> data is collected during this process; only an opaque device identifier
> derived from the attestation key is stored on our servers.

## 12. Rollout plan

### Week of 11/08 — Foundation

Owner: Uriel. Deliverable: WAF live in dev, App Attest bootstrap tested
end-to-end in dev.

| Day | Task | Deliverable |
|---|---|---|
| Mon 11/08 | Onboarding. Read `CLAUDE.md`, `docs/architecture-diagram.md`, `issues.md`, and the handover deck at `~/Documents/24defend/handover-presentation.html`. Verify AWS access, run backend + iOS app locally. | Slack message confirming environment is up. |
| Tue 12/08 | **PR #1**: AWS WAF Web ACL via CDK, attached to the dev ALB. Common Rule Set + rate-limit rule (100 requests / 5 min per IP). Deploy to dev via `cdk deploy`. Test with `ab -n 200 -c 10 https://api.24defend.com/health` — expect 429s after ~100. | PR merged. CloudWatch screenshot of blocked requests. |
| Wed 13/08 | iOS: `ios/Shared/DeviceAuth.swift`. Implement `bootstrap()` — key generation via `DCAppAttestService.generateKey()`, Keychain storage of the keyId. `#if DEBUG` bypass path returning a static token. | File in the repo. Called from `TwentyFourDefendApp` on first launch. keyId visible in Xcode Keychain viewer. |
| Thu 14/08 | Backend: `POST /auth/challenge` returning a 32-byte random nonce with 5-min TTL (in-memory cache). `POST /auth/register` verifies attestation against Apple, writes to new DDB table `24defend-devices` (defined in `infra/stack.py`). | **PR #2** merged. Manual `curl` register-flow succeeds. DDB item visible via `aws dynamodb scan`. |
| Fri 15/08 | End-to-end integration test in dev: uninstall app on device, reinstall, verify attestation succeeds, DDB row exists with correct fields. Update this doc with any decisions made during implementation. | Screenshot demo posted to Slack. Doc updated. |

### Week of 18/08 — Enforcement

Owner: Uriel. Deliverable: hard enforcement live in dev, dual-mode
enforcement live in prod, cutover complete by Friday.

| Day | Task | Deliverable |
|---|---|---|
| Mon 18/08 | iOS: `DeviceAuth.sign(request:)` — extends every `URLRequest` with `X-Defend-Device-Id`, `X-Defend-Assertion`, `X-Defend-Timestamp` headers, using `generateAssertion`. Wire into `APIClient.swift`. | All API calls carry signing headers against dev API. |
| Tue 19/08 | Backend: `require_device_auth` FastAPI dependency in `backend/app/middleware/device_auth.py`. Verifies assertion using Apple's counter-based scheme. Rejects with 401 on failure. Applied to `/check`, `/bloom-filter/*`, `/daily-blacklist`, `/daily-false-positives`, `/telemetry/events`. | **PR #3** merged. Unauthenticated `curl` → 401. Signed request → 200. |
| Wed 20/08 | Deploy to **prod** in dual mode: middleware accepts BOTH signed and unsigned, logs unsigned as `UNSIGNED_REQUEST` with User-Agent for observability. | Deployed. CloudWatch dashboard showing signed vs unsigned split for the first 24h. |
| Thu 21/08 | Per-device rate limits (in-memory sliding-window counter). Values per section 6. Return 429 with `Retry-After`. | **PR #4** merged. Load test showing 100 req/min per device passes, 101st gets 429. |
| Fri 22/08 | Cutover to **hard enforcement** in prod: reject unsigned requests EXCEPT for User-Agent matching pre-14 app builds (grace period for testers who haven't updated). Monitor CloudWatch for 24h. | Cutover complete. Rollback procedure documented in `docs/runbook-auth-cutover.md`. |

### Week of 25/08 — Stabilization with F&F testers

Owner: Uriel + support from full team as issues surface. Deliverable: no
tester reports of connectivity issues attributable to auth, rate limits
tuned to real observed traffic.

- Daily review of WAF logs for false positives (legit users getting
  rate-limited).
- Daily review of auth failures. Expected near zero. Anything else is a bug.
- Tune per-device rate limits if any legitimate user hits them.
- Test the revocation flow end-to-end (admin CLI to revoke → client
  observes 403 → modal shown → VPN disabled).
- Retro at end of week with team.

### Week of 01/09 — Optional upgrades

Owner: Uriel. Only if signal from stabilization justifies the work.

- If unauthenticated bot traffic is significant despite the L1+L2+L3 stack:
  enable AWS WAF Bot Control managed rule ($10/mo + volume).
- If bandwidth cost from `GET /bloom-filter/*` becomes visible: put
  CloudFront in front of the ALB.
- Retrospective + writeup for the team.

### Week of 08/09 — App Store submission prep

Owner: Uriel (technical), Maximo (App Store Connect + policy). Deliverable:
submission-ready build.

- Uriel: verify Privacy Manifest with `plutil -p`.
- Maximo: update App Privacy questionnaire in App Store Connect (add
  Device ID data type).
- Maximo: update privacy policy at `www/privacy-es.html`.
- Maximo: draft App Store Review notes covering diagnostic panel + App
  Attest bootstrap.
- Full regression test on TestFlight build.
- Submit to App Store on Friday 12/09.

### Week of 15/09 — Launch

- Respond to App Review feedback if any (typical latency 24-48 h).
- Coordinated public launch when approved.

## 13. Definition of done

**End of week 1 (15/08)**

- WAF Web ACL live in dev, rate-limiting confirmed via load test.
- Fresh install of the app → attestation succeeds → DDB row exists.
- `#if DEBUG` bypass path works when running from Xcode locally.

**End of week 2 (22/08)**

- Dual-mode enforcement live in prod.
- All API calls from build ≥ 14 include signing headers.
- Unsigned requests logged for observability.
- `docs/runbook-auth-cutover.md` describes rollback in one page.

**End of week 3 (29/08)**

- Zero support reports of "app broken because of auth."
- Rate limits tuned to observed p99 traffic patterns.
- Revocation flow tested end-to-end.

**End of week 5 (12/09)**

- App Store submission accepted for review.
- All three consistency artifacts (code / privacy policy / App Privacy
  questionnaire) declare the same device-ID collection.

**Launch (15/09 or shortly after)**

- App approved and live in the App Store.
- WAF + Auth stack running in prod with clean CloudWatch metrics.

## 14. Open decisions

1. **AWS-native vs Cloudflare for L1.** Decided: AWS-native (WAF, optionally
   CloudFront later). Reasons: Uriel already has AWS access, everything
   through CDK, single account, no Cloudflare vendor dependency.
2. **Public web-check page.** Decided: NOT in this scope. If we ever add it,
   it lives as a separate service with its own bot protection.
3. **Expose deviceId in the app UI.** Decided: not by default. Consider
   showing in the diagnostic view (7-tap panel) so support can ask
   "give me your device ID" when triaging a report.
4. **JWT rotation optimization** (avoid per-request `generateAssertion`).
   Decided: defer. 50 ms overhead per API call is not a UX issue at
   current scale.
5. **Enforcement aggressiveness during F&F testing.** Decided: dual-mode
   from 20/08, hard cutover 22/08. Testers on pre-build-14 apps get a
   grace period detected via User-Agent, then must update.

## 15. References

Apple:
- [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
- [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [DCAppAttestService API](https://developer.apple.com/documentation/devicecheck/dcappattestservice)

AWS:
- [AWS WAF Web ACL setup](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html)
- [AWSManagedRulesCommonRuleSet](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
- [Rate-based rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)

Files that will be touched or created (for planning purposes):

- `ios/Shared/DeviceAuth.swift` — new
- `ios/Shared/APIClient.swift` — integrate `DeviceAuth.sign(request:)`
- `ios/TwentyFourDefend/TwentyFourDefendApp.swift` — call
  `DeviceAuth.bootstrap()` on first launch
- `backend/app/routes/auth.py` — new (`/auth/challenge` + `/auth/register`)
- `backend/app/middleware/device_auth.py` — new
- `backend/app/routes/check.py`, `bloom.py`, `daily.py`, `telemetry.py` —
  add `require_device_auth` dependency
- `backend/app/config.py` — add `apple_team_id`, `apple_bundle_id`
- `infra/stack.py` — add DDB table `24defend-devices` + WAF Web ACL
- `www/privacy-es.html` — one sentence about the device identifier
- `docs/runbook-auth-cutover.md` — new, one-page rollback procedure
- `docs/design/api-authentication.md` — this document

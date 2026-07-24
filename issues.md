# Known issues & improvements

Lightweight backlog until we set up a proper tracker.

---

## LLM

### Support LLM rotation for rate limits

The agent (`app/investigation/graph.py`) uses a single Bedrock model
(`settings.bedrock_model_id`, currently `zai.glm-4.7`). If Bedrock
throttles the account or the model goes into a Marketplace rate-limit
window, every `/check` that reaches the agent fails.

**Fix idea:** accept a comma-separated `DEFEND_BEDROCK_MODEL_IDS` env
(e.g. `zai.glm-4.7,us.anthropic.claude-sonnet-4-6,zai.glm-4.7-flash`).
On agent invocation:
1. Try model[0].
2. On `ThrottlingException` / `TooManyRequestsException` /
   `ModelStreamErrorException`, fall back to model[1], and so on.
3. Cache the "last-good" model for a short window so we don't spin the
   rotation on every call after a partial recovery.

Also emit a metric per model per outcome so we can see rotation
frequency in CloudWatch.

## Dev workflow

### No local-dev loop for the API

Right now the only way to test backend changes is: Docker build → push
to ECR → ECS force-new-deployment → wait ~5-8 min → curl. That's a
brutally slow iteration loop, especially for prompt tweaks and small
agent-behavior changes. We hit this hard during the FP debugging pass
— each prompt iteration cost a full deploy cycle.

**Fix idea:** set up `uvicorn app.main:app --reload` runnable from
`backend/` with:
- `.env.local` pattern for AWS creds + Bedrock region + fake DynamoDB
  endpoint (or a real DDB session).
- Optional lightweight DDB local (`amazon/dynamodb-local`) OR flag to
  use the real dev DDB table with a scoped prefix.
- Skip the Majestic load and heavy ingestion by default (add a
  `DEFEND_SKIP_STARTUP_INGESTION=true` flag).
- Small make target: `make dev` — starts the server, prints the curl
  one-liner.

Then package as a Claude skill `.claude/skills/local-dev-api.md` so
future work has a `/local-dev-api` slash command instead of re-figuring
this out.

---

## Infra

### CI deploy workflow is broken

`.github/workflows/deploy.yml` fails at "Configure AWS credentials" on every
push to `main` and has been failing since May 2026. The workflow assumes
OIDC to `${{ secrets.AWS_DEPLOY_ROLE_ARN }}` — that secret was never set
on the repo (or the OIDC identity provider was never configured on the
AWS account).

**Impact:** none for now — we deploy manually via `/deploy-backend-fast`
(`.claude/skills/deploy-backend-fast.md`). But git push to main silently
red-Xs the check and we ignore it.

**Fix:**
1. In AWS: create an OIDC provider for `token.actions.githubusercontent.com`
   in the target account (081856108753 for dev).
2. Create IAM role `github-actions-deploy` with trust policy scoped to
   `repo:andresgurmendez/24defend:ref:refs/heads/main`.
3. Attach a policy allowing ECR push + ECS update-service + CDK deploy.
4. Add repo secret `AWS_DEPLOY_ROLE_ARN` with the role ARN.

### `/deploy-backend-fast` silently corrupts the `:latest` push

Observed multiple times: `docker push $REGISTRY/$REPO:latest` inside the
skill's shell block fails with `The repository with name
'defend-dev-backendatest' does not exist` — the `:l` gets eaten,
`latest` becomes `atest`. The `:$SHA` push in the same script works
fine. The literal-URL version (no shell interpolation) also works.
Root cause is somewhere between zsh interpolation and docker's CLI
arg parsing — not fully diagnosed.

The failure mode is silent-catastrophic: `set -e` exits, but the
SHA-tagged push already succeeded, and the CDK task pulls `:latest`
which is stuck at the digest from the last time the tag correctly
updated. Multiple code changes never actually reached production;
`curl` tests kept showing "old" behavior because the container was
literally running an old image. Wasted ~1 hour of debugging.

**Workaround:** after any `/deploy-backend-fast`, verify with
`aws ecr describe-images ... imageTag=latest` that the returned
digest matches your freshly-built SHA. If it doesn't, manually retag
with literal URLs (no `$VAR`).

**Proper fix:** pin the image digest into the task def (register-task-definition
or CDK asset) so `:latest` is never load-bearing.

---

## Backend

### `/check` is synchronous — cold agent calls exceed reasonable client timeouts

Today `/check` blocks on `investigate_domain` when the domain is unknown
(not in blacklist/whitelist/cache). A cold agent run takes ~40s. The iOS
`APIClient` was originally set to a 5s timeout — bumped to 45s as a
band-aid, but 45s of held DNS is a bad UX regardless.

The observed failure mode (real, from testing premios.oca.hk on device):
1. iOS brand rule fires → `.warned` verdict.
2. Tunnel holds DNS and calls `/check` for confirmation.
3. Backend agent needs 40s. Client times out at 5s. Falls back to
   client's original warn verdict → user sees "Suspicious", not "Blocked".
4. Backend finishes at 40s, caches the correct "block" verdict — too late
   for this visit, correct for the next one.

**Proposed pattern:**
1. `/check` becomes **cache-only** — returns whatever the DB knows
   (blacklist / whitelist / cache) or `verdict=unknown` if nothing hit.
   Always fast (<1s).
2. New `/investigate` (fire-and-forget from client) queues an agent run.
   Result gets cached — next visit sees the confirmed verdict.
3. iOS: when `/check` returns "unknown", the tunnel decides based on the
   local heuristic (warn/allow) AND fires `/investigate` in the
   background. Optionally, the agent's block verdict can trigger a
   retroactive push notification via the existing `should_notify` path
   (once that field ships end-to-end).

This aligns with the ML-flag path already in `PacketTunnelProvider.swift:313`
which uses `Task.detached { _ = await APIClient.checkDomain(domain) }`
(fire-and-forget). The brand-warn path should adopt the same shape.

### Backend has no popular-domain short-circuit

`/check` falls through to the full agent path for any domain not in
blacklist/whitelist/cache — including obviously-safe ones. The iOS
`DomainChecker.infrastructureSet` (~90 hardcoded) already short-circuits
the common cases on-device, so this rarely bites the app in practice.
But it does mean:

- Non-app callers (curl, admin tools, future partner integrations) pay a
  40s+ agent invocation for every fresh popular domain.
- ML classifier false positives on popular-but-obscure domains (regional
  CDNs, LatAm services not in the hardcoded 90) bypass the client filter
  and waste a Bedrock call each.
- We already download Majestic Million top 100K during ingestion (see
  `_fetch_popular_domains` in `app/ingestion/runner.py`) — the data is
  right there.

**Fix (small):** module-level singleton `app/popular_domains.py` loaded on
startup from Majestic Million, refreshed each ingestion cycle. Add a
`is_popular(domain)` check in `routes/check.py` between the DB lookup
and the agent invocation — return `verdict=allow`, `source=popular` if
hit.

Alternative lighter version: one-shot `put_domains_bulk` of
`SHARED_INFRASTRUCTURE_DOMAINS` into the whitelist table.

### `should_notify` missing from `/check` responses

Empirically, the `should_notify` field in `DomainCheckResponse` doesn't
appear in the returned JSON even when the code sets it (e.g., blacklist
path in `routes/check.py:46` sets `should_notify=True` but the response
body omits it). Likely a Pydantic serialization exclusion or an old
response model on the client. iOS uses this to decide whether to send
the retroactive user notification, so it matters once notifications go
live.

**Fix:** check Pydantic model config on `DomainCheckResponse`; verify
`model_dump` behavior; add a test asserting the field is present on
each path.

---

## Product / iOS

### Can't filter DNS by source app (browser vs background)

`NEPacketTunnelProvider` (our current extension type) receives raw IP
packets from the kernel — it has no way to know which app / bundle ID
generated each DNS query. So we can't scope our analysis to "only what
the user is actually browsing" vs "background API calls from other
apps." The observed effect: our per-session query counts include a
huge tail of app telemetry, analytics, and background fetches that
the user never intended to hit.

**What we already do:** the popular-domain allowlist (backend
`app/popular_domains.py`, Majestic top 100K) and the
`DomainChecker.infrastructureSet` on-device filter absorb most of the
noise before it reaches the classifier. That is doing a lot of work.

**What could go further:**
1. Switch to `NEFilterDataProvider` (content-filter extension). That
   extension type DOES see `NEFlowMetaData.sourceAppUniqueIdentifier`
   / `sourceAppSigningIdentifier`, so we could scope enforcement to
   browsers only. Trade-offs: different architecture, filters TCP/UDP
   flows instead of raw DNS, has its own memory limit, cannot easily
   coexist with a packet tunnel. This is a real re-arch, not a tweak.
2. Grow the on-device denylist of "boring" domains (analytics
   endpoints, CDN telemetry hostnames) so the ML classifier never
   sees them. Cheap and additive; doesn't require an extension swap.
3. Per-app VPN via `NEAppRules` — App Store apps don't get this;
   it needs MDM / enterprise provisioning.

Leaving as reference: right now the popular-domain path is enough,
but if we ever want "browsing-only" scoping we'd have to look at (1).

### Uncommitted BlockDetailView share-button change already shipped

Was a long-standing pending item — done in commit `<insert-sha>` (share
button only appears when `severity == .red`). Leaving this here as a
marker in case we want to revisit the UX (e.g., a lighter "flag it"
option for warn severity).

---

## Notes

- Add issues here as we hit them. When this file has more than 10-15
  entries, or we bring on a second person actively triaging, migrate to
  GitHub Issues / Linear.
- Prefer one paragraph of context per issue over "TODO: fix X". The
  context is what makes an issue re-openable weeks later.

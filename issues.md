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

### Agent doesn't know about corporate parent/subsidiary relationships

Observed FP: `pedidosya-api.dhmedia.io` was cached as verdict=block with
the agent reasoning "dhmedia.io no tiene nada que ver con el servicio
real" — factually wrong. Delivery Hero (dhmedia.io / deliveryhero.com)
IS the parent company of PedidosYa and serves legit PedidosYa API/CDN
endpoints from that infrastructure.

Root cause: the agent sees a known brand keyword ("pedidosya") in a
subdomain of a domain it doesn't recognize, and concludes impersonation.
It has no signal for "this apparently-unrelated domain is actually owned
by the same corporate group."

Immediate fix: added dhmedia.io + deliveryhero.com to VENDOR_ALLOWLIST
in `app/popular_domains.py`. Same class of fix as pokeapi.co — the
popular-domain short-circuit runs before the DB lookup, so the bad
cached verdict never wins.

Longer-term fix ideas:
1. Bake a small "known parent groups" map into the agent's system
   prompt: `{"pedidosya": ["dhmedia.io", "deliveryhero.com"],
   "instagram": ["fbcdn.net"], "youtube": ["googlevideo.com"],
   ...}`. Cheap in tokens, high accuracy on this class of FP.
2. Add a `WHOIS_OWNERSHIP_CHECK` tool that queries the base domain's
   registrant/organization. If the registrant matches a known parent
   company of the brand the agent is worried about, mark as legit.
   More robust than a static map but adds latency + external dep.
3. Track "brand corporate group" as a first-class concept in the
   whitelist DB and expand the brand rule engine to check against
   parent groups, not just exact brand match.

Also worth: sweep the cache table periodically for entries where the
base domain was later added to VENDOR_ALLOWLIST and delete them, so
we don't leave stale bad rows behind (functionally harmless because
of the reorder, but keeps DDB clean).

### test_ingestion.py hangs / times out under full-suite runs

`.venv/bin/pytest -q` (with only `--ignore=tests/test_agent.py`) hangs
inside `tests/test_ingestion.py`, apparently blocking on a real HTTP
call to one of the public threat feeds (Phishing.Army, URLhaus,
OpenPhish, PhishTank). Predates the resolve_domain work — reproduced
on `main` before my staged changes were applied.

Workaround: `pytest --ignore=tests/test_agent.py --ignore=tests/test_ingestion.py`
(175 tests, ~0.4s).

Fix: mock the httpx.Client calls inside `app.ingestion.sources.*`
in a `conftest.py`-level autouse fixture, OR add `pytest-timeout`
to `requirements-dev.txt` and set a per-test timeout (5s) in
`pytest.ini` so a hung fetch aborts loudly instead of stalling CI.

### Yellow-never-green: additional levers we discussed but deferred

Ships now: when the agent verdict is `warn`, close the loop with a
"checked but inconclusive" notification (see the shipped .checked
severity + new copy). Below is the rest of the design space we
weighed and chose not to implement yet.

**A. Bias agent toward decisive verdicts (prompt refinement).** Warn
should be reserved for "tools returned genuinely conflicting evidence."
Force block / allow otherwise. Cost near-zero. Risk: agent forced to
allow when it should have warned → could add FPs. Do this once we
have data on how often the current agent produces warn in production.

**C. Extend polling window.** `PendingInvestigation.expirySeconds`
is currently 600 (10 min). Cold agent runs + network retries can
exceed that, and the entry silently drops. Bumping to 1800 (30 min)
would give the agent more room without any UX cost. Trivial change;
worth pairing with the poll-expiry "we couldn't reach the server"
notification (see below).

**D. Server-side resolve warn → block/allow.** Second-pass agent
run (different LLM / more tools / longer context) whenever the first
pass returned warn. Cache only the final decisive verdict; never
persist warn. Biggest architectural fix but adds Bedrock spend per
warn. Best long-term.

**E. Downgrade warn → soft-green after N polls.** If we see 3
consecutive warn responses with no block in between, promote to
green with softer copy. Risk: false-clearing real phishing. Not
recommended alone — safer as a companion to A + D.

**F. Different treatment by yellow origin.** BK-tree-fuzzy-match
yellows ("similar to whitelist") + agent warn are almost always
legit long-tail domains — could auto-promote to a soft-green after
warn. Brand-rule yellows (explicit brand keyword) + agent warn
should stay amber. Needs threading the yellow origin from the tunnel
down to `PendingInvestigation`, then branching on it in the poll
handler. Moderate effort.

**G. Poll-expiry "we couldn't reach the server" notification.**
When `expirySeconds` elapses with no decisive verdict at all
(neither block nor allow nor warn — usually a network unreachable
situation), fire an explicit notification instead of the current
silent drop. Different copy from the warn case: "No pudimos
completar la revisión de <domain> — puede haber sido un problema
de red. Andá con cuidado." Small change.

### Cache de veredictos envenenados del período pre-hardening

Entre el 2026-07-26 (deploy de resolve_domain) y el 2026-07-28 20:00
aprox (deploy de la regla MANDATORY resolve_domain + DEFINITIVE TLS
Subject O como señal legit), el agente tenía la evidencia pero no
la regla dura de usarla. Cacheó veredictos `block` con
`should_notify=true` en dominios legítimos (ej: `print1.mercadoclics.com`,
que hoy con el prompt hardened el agente probablemente no bloquearía).

TTL de esos entries: ~60 días desde `checked_at`. Sin intervención,
usuarios verán rojos por dominios legítimos hasta ~2026-09-24.

Fix idea: script one-shot que scanee la tabla DDB filtrando
`entry_type=cache AND verdict=block AND should_notify=true AND
checked_at < '2026-07-28T20:00Z'`, y para cada match:
1. Verificar si el base domain ya está en VENDOR_ALLOWLIST → si sí, borrar entry.
2. Re-invocar el agente actual → si devuelve allow/warn, borrar/reemplazar.
3. Si el agente todavía dice block, dejar como está.

Alternativa manual: cada FP reportado se agrega a VENDOR_ALLOWLIST
(lo que estamos haciendo). Menos completo pero cero riesgo.

## Dashboard

### Internal metrics dashboard: polish deferred from PR #7 review

`harmatrix` review flagged 8 findings; fixed the 4 🚨 (auth on
`/telemetry/stats`, real login + route guard, CORS default no longer
whitelisting localhost in prod, private S3 + CloudFront OAC for
`DashboardBucket`) before merging. Deferring the 4 🟡:

- **`cdk synth`/`deploy` reads `../frontend/dist` at synth time**
  (`s3deploy.BucketDeployment` in `infra/stack.py`). A clean checkout
  without a prior `npm run build` fails synth, or worse, ships stale
  artifacts already on disk. Fix idea: a `/deploy-dashboard` skill (or
  Makefile target) that always runs `npm ci && npm run build` in
  `frontend/` right before `cdk deploy`, or switch to CDK's own
  `NodejsBuild`/bundling so the build happens inside the CDK asset
  step instead of being an out-of-band precondition.
- **No `.env.development`** — Vite falls back to `.env.production`
  (`VITE_API_BASE=https://api.24defend.com`) for local dev too, so a
  dev running the dashboard against a local backend has to hand-edit
  env files. Fix: add `frontend/.env.development` pointing at
  `http://localhost:8000`, document the override in
  `frontend/README.md`.
- **`DashboardBucket` has `RemovalPolicy.DESTROY` (dev) without
  `auto_delete_objects=True`** — `cdk destroy` fails on a non-empty
  bucket, same as the pre-existing `WwwBucket` (this isn't a
  regression, just an existing footgun this PR inherited). Fix:
  `auto_delete_objects=not is_prod` alongside the existing
  `removal_policy` conditional.
- **`DashboardPage.load()` has no `AbortController`** — a manual
  refresh firing while a previous fetch is still in flight can let the
  older response resolve after the newer one and overwrite fresh state
  with stale data. Fix: standard
  `AbortController` + `useEffect` cleanup around the `fetch` calls in
  `lib/api.ts`.

None of these are security-critical the way the 4 🚨 were — worst case
is a confusing deploy failure, dev friction, a stuck `cdk destroy`, or
a rare stale-overwrite render glitch.

## Notes

- Add issues here as we hit them. When this file has more than 10-15
  entries, or we bring on a second person actively triaging, migrate to
  GitHub Issues / Linear.
- Prefer one paragraph of context per issue over "TODO: fix X". The
  context is what makes an issue re-openable weeks later.

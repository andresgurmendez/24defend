# Known issues & improvements

Lightweight backlog until we set up a proper tracker.

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

# Troubleshooting

Common errors and their fixes, grouped by area. For each entry: **symptom →
likely cause → fix**. Run the relevant skill (`/status`, `/logs-backend`,
`/onboard-new-dev`) before assuming the system is broken.

Cross-references:
- AWS keys: [aws-keys.md](aws-keys.md)
- Architecture overview: [architecture-diagram.md](architecture-diagram.md)
- Full architecture: [../architecture.md](../architecture.md)
- Project patterns and footguns: [../CLAUDE.md](../CLAUDE.md)
- First-day setup: [../ONBOARDING.md](../ONBOARDING.md)

---

## Local development

### `docker compose up` fails: port 9147 already in use

**Symptom**: `Bind for 0.0.0.0:9147 failed: port is already allocated`.

**Cause**: another process owns 9147 (the host port for the API container).

**Fix**:
```bash
lsof -i :9147
kill <pid>
# or edit backend/docker-compose.yml to map a different host port
```

### `docker compose up` fails: port 8000 already in use

**Symptom**: `Bind for 0.0.0.0:8000 failed: port is already allocated`.

**Cause**: `dynamodb-local` listens on 8000; commonly collides with other
local dev tools (Jupyter, Django dev server, etc.).

**Fix**: stop the other tool, or remap in `backend/docker-compose.yml`:
- change host port: `8765:8000`
- update `DEFEND_DYNAMODB_ENDPOINT` env var to match

### API container starts but `/check` returns 500 immediately

**Symptom**: `curl http://localhost:9147/check ... → 500 Internal Server Error`.

**Cause**: Bedrock call failed because AWS creds aren't loaded inside the
container. `docker compose` reads env at startup; if you `source aws.sh`
*after* `docker compose up`, the running api container does not have them.

**Fix**:
```bash
source aws.sh
cd backend
docker compose up -d --force-recreate api
```

### DynamoDB local has no data after restart

**Symptom**: domains you added via `/admin` are gone after restart.

**Cause**: `dynamodb-local` uses `-inMemory`. Intentional. Data resets every
restart.

**Fix**: not a bug. To populate quickly:
```bash
DEFEND_API_KEY=dev-api-key-change-me \
  python3 scripts/seed_uruguay.py http://localhost:9147
```

### Uvicorn doesn't reload on Python file changes

**Symptom**: edit a `.py` file, no log line about reload, behavior unchanged.

**Cause**: dev compose may not pass `--reload`, or the file is mounted from a
path Docker doesn't watch.

**Fix**: verify the api service in `backend/docker-compose.yml` uses
`--reload` and mounts `./app` into the container. If running outside compose,
`uvicorn app.main:app --reload`.

### Backend venv missing or broken

**Symptom**: `/test-backend` says `backend/.venv exists FAIL`, or
`import fastapi` errors.

**Fix**:
```bash
cd backend
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-test.txt
```

Always use Python 3.12 — the Dockerfile pins it. 3.11/3.13 may import but
will silently disagree with prod on async edge cases.

---

## iOS

### `xcodegen generate` blew away my Info.plist

**Symptom**: app launches with the wrong display name, or the packet tunnel
extension fails to load (`NSExtension` dict gone).

**Cause**: xcodegen overwrites both `Info.plist` files every run. This is
*the* most common iOS footgun in this repo.

**Fix**:
```bash
cd ios
git diff TwentyFourDefend/Info.plist TwentyFourDefendPacketTunnel/Info.plist
git checkout TwentyFourDefend/Info.plist TwentyFourDefendPacketTunnel/Info.plist
```
Restore:
- App plist: `CFBundleDisplayName = "24Defend"`
- Tunnel plist: full `NSExtension` dict with `NEPacketTunnelProvider`

Or use the `/ios-build` skill, which encodes the restore step.

### NetworkExtension does nothing in the simulator

**Symptom**: app runs, UI works, but no DNS is being intercepted; toggling
the VPN switch is silent.

**Cause**: iOS Simulator does not support `NEPacketTunnelProvider`. The UI
runs; the tunnel does not.

**Fix**: not a bug. For real testing, install on a physical device. See
`ios/DISTRIBUTION.md`.

### Cross-validation Swift tests fail (mmh3 / features)

**Symptom**: `test_cross_validation*` failing in Xcode.

**Cause**: Swift `BloomFilter.swift` or feature extractor drifted from the
Python ground truth, or the ground-truth JSON is stale.

**Fix**:
- If Python was the source of truth, regenerate:
  ```bash
  cd ml && .venv/bin/python train.py
  ```
- If Swift drifted: compare `BloomFilter.swift` `pythonMod` (signed int32
  modulo, *not* unsigned) against Python's behavior. See
  [CLAUDE.md](../CLAUDE.md) "Signed modulo".

### Code signing failure on simulator build

**Symptom**: `xcodebuild` complains about provisioning profile on a
simulator build that shouldn't need one.

**Cause**: a development team got written into `project.yml`, or stale
DerivedData has cached signing state.

**Fix**:
```bash
rm -rf ~/Library/Developer/Xcode/DerivedData/TwentyFourDefend-*
# verify project.yml has no devTeam or signing block for simulator targets
xcodegen generate
```

### `xcodebuild` says "no such destination"

**Symptom**: simulator destination string rejected.

**Cause**: iPhone 15 runtime not installed, or wrong destination format.

**Fix**:
```bash
xcrun simctl list devicetypes
xcodebuild -showsdks
```
Use a destination that actually exists. `name=iPhone 15` is the generic
form Xcode resolves automatically.

---

## Backend

### Bedrock returns 429 / `ThrottlingException`

**Symptom**: log lines `Retrying...`, `429`, `ThrottlingException`, slow
agent responses.

**Cause**: AWS Bedrock per-account TPS limits on the configured Claude model
(`claude-3-5-sonnet`-style id).

**Fix**:
- Wait — most are transient.
- For sustained throttling, request a quota increase (AWS console → Service
  Quotas → Bedrock).
- For dev, consider switching the model env var to a Haiku id, which has
  more headroom and is fine for testing:
  ```bash
  DEFEND_BEDROCK_MODEL_ID=us.anthropic.claude-haiku-... docker compose up
  ```

### Agent caches a wrong verdict in DynamoDB

**Symptom**: `/check yourdomain.com` returns `verdict=warn` or `block` for a
domain you know is legitimate (e.g., a CDN, an ad-tech endpoint), and the
verdict persists across requests.

**Cause**: agent ran an investigation and persisted an incorrect cached
verdict in the `24defend-domains` table.

**Fix**: use `/clear-cached-verdict <domain>`. The next `/check` will
re-investigate. If the agent keeps returning the same wrong verdict, the
prompt may need a fix — see `backend/app/investigation/graph.py` and
[CLAUDE.md](../CLAUDE.md) "Agent prompt — ad-tech / CDN awareness".

### `/check` is slow (>5 seconds) for an unknown domain

**Symptom**: `/check` on a domain not in DynamoDB takes 15–30 seconds.

**Cause**: expected — that's an agent investigation (DNS, RDAP, SSL, search,
heuristics, Bedrock call). Subsequent calls hit the cache (~50 ms).

**Fix**: not a bug. If it's >30 seconds, check `/logs-backend errors` for
tool failures.

### ALB returns 504 Gateway Timeout for long requests

**Symptom**: a manual `/admin/ingest/blacklists` call returns 504 after
60 seconds.

**Cause**: ALB idle timeout is 60 seconds. Long admin jobs run server-side
beyond that.

**Fix**: fire-and-forget. The job completes regardless of the client-side
timeout. Verify completion via logs:
```bash
/logs-backend 200 | grep -i ingestion
```
Scheduled jobs (daily ingestion at 03:00 UTC) run in-process with no ALB
involvement, so they're unaffected.

### `ListTables AccessDeniedException` on container startup

**Symptom**: backend logs show `botocore.exceptions.ClientError: ... ListTables`
on Fargate startup.

**Cause**: old code that tried to create DynamoDB tables at startup. The
table is now CDK-managed; `ensure_table()` should skip creation when
`DEFEND_DYNAMODB_ENDPOINT` is unset (prod).

**Fix**: deploy a fresh image. The current code path doesn't call
`ListTables` in prod.

### Daily ingestion didn't run

**Symptom**: `/admin/bloom-filter/stats` shows old timestamps; no
`Ingestion completed` line in logs around 03:00 UTC.

**Cause**: APScheduler runs in-process. If the container restarted at the
wrong moment, the job can be missed (it does not catch up automatically).

**Fix**: trigger manually:
```bash
curl -s --max-time 5 -X POST https://api.24defend.com/admin/ingest/blacklists \
  -H "X-Api-Key: dev-api-key-24defend"
# ALB will time out at 60s; server keeps running. Watch /logs-backend.
```

---

## Deployment

### `exec format error` in ECS task logs

**Symptom**: ECS task fails to start; CloudWatch shows
`exec /usr/local/bin/python: exec format error`.

**Cause**: image built for ARM (Mac default) instead of AMD64. Fargate is
AMD64.

**Fix**: always build with `--platform linux/amd64`:
```bash
docker build --platform linux/amd64 -t ... backend/
```
The Dockerfile also pins `FROM --platform=linux/amd64`; never remove that.

### CDK doesn't rebuild after a code change

**Symptom**: `/deploy` finishes, but the deployed container still shows old
behavior. Image digest in ECS is unchanged.

**Cause**: CDK hashes the `backend/` directory to decide whether to rebuild.
If only `.pyc` files changed (or some other ignored content), it skips.

**Fix**: bump the `# Force rebuild: YYYY-MM-DD` comment line in
`backend/Dockerfile`. This changes the hash and forces a rebuild.

### ECS service stuck in `CREATE_IN_PROGRESS`

**Symptom**: CloudFormation stack stays in `CREATE_IN_PROGRESS` for >10 min;
ECS tasks keep starting and dying.

**Cause**: container can't reach steady state — bad env var, missing secret,
exec format error, can't connect to DynamoDB.

**Fix**:
1. `/logs-backend errors` — read the latest failures.
2. Check task stop reason:
   ```bash
   aws ecs describe-tasks --cluster defend-dev-cluster --tasks <arn> \
     --region us-east-1 \
     --query 'tasks[0].containers[0].{lastStatus: lastStatus, exitCode: exitCode, reason: reason}'
   ```
3. If hopelessly stuck (CFN won't budge for 30 min), see
   `.claude/skills/deploy.md` "Nuclear option" section.

### Secrets Manager values are empty after deploy

**Symptom**: container starts but env vars are empty strings; `/check` 500s
because API key check fails.

**Cause**: Secrets Manager secret was created by CDK but never populated.
The Fargate task pulls secrets *at startup*; if they're empty, the env vars
are empty.

**Fix**: populate immediately after `cdk deploy`:
```bash
aws secretsmanager put-secret-value \
  --secret-id "defend-dev/api-key" \
  --secret-string "dev-api-key-24defend" \
  --region us-east-1
aws secretsmanager put-secret-value \
  --secret-id "defend-dev/serper-api-key" \
  --secret-string "$(cat ~/git/24defend-mono/serper.conf)" \
  --region us-east-1
# Force ECS to pick them up:
aws ecs update-service --cluster defend-dev-cluster \
  --service defend-dev-backend --force-new-deployment --region us-east-1
```

### CI workflow fails at "Configure AWS credentials"

**Symptom**: GitHub Actions deploy workflow red at the AWS auth step.

**Cause**: known — `AWS_DEPLOY_ROLE_ARN` secret was never set on the repo.

**Fix**: don't rely on CI for deploys. Use `/deploy-backend-fast` or
`/deploy` locally. To fix CI: tech lead must (a) create an OIDC trust between
GitHub and AWS, (b) set the `AWS_DEPLOY_ROLE_ARN` secret on the repo.

### ECR push fails: `no basic auth credentials`

**Symptom**: `docker push ...ecr...amazonaws.com/...` fails immediately.

**Cause**: ECR login token (12-hour TTL) expired.

**Fix**:
```bash
source aws.sh
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 081856108753.dkr.ecr.us-east-1.amazonaws.com
```

---

## AWS keys

See [aws-keys.md](aws-keys.md) for the full guide (rotation, security
guidelines, two-account model). Quick references:

| Symptom                                | Fix                                                          |
|----------------------------------------|--------------------------------------------------------------|
| `Unable to locate credentials`         | `source /Users/mgurmendez/git/24defend-mono/aws.sh`           |
| `ExpiredToken`                         | Re-run `aws sso login`, or get fresh keys                    |
| `InvalidClientTokenId`                 | Key id wrong or deleted — verify with tech lead              |
| `aws sts` shows wrong account ID       | `aws.sh` has wrong keys — replace                            |
| `AccessDenied` on a single service     | IAM policy gap — ask tech lead, do not modify policy yourself |

---

## Bloom filter / detection pipeline

### CDN domain blocked / warned

**Symptom**: `cdn.something.cloudflare.net`, `c.ltmsphrcl.net`, or similar
returns a warn or block.

**Cause**: usually one of:
1. Cached bad agent verdict in DynamoDB (most common — see "Agent caches a
   wrong verdict" above).
2. Domain not in the infrastructure allowlist
   (`ios/Shared/DomainChecker.swift`).
3. Bloom filter false positive that the API confirmation logic should have
   caught but didn't.

**Fix order**:
1. `/clear-cached-verdict <domain>` to wipe DynamoDB.
2. If the base domain (after `extractBaseDomain()`) is a known CDN / ad-tech
   provider, add it to `DomainChecker.swift` infrastructure set. See
   [CLAUDE.md](../CLAUDE.md) "Infrastructure allowlist".
3. If it's a real bloom FP, the device should learn it via
   `GET /daily-false-positives` within 30 minutes. To force immediately,
   `/clear-cached-verdict` and let the next check confirm allow.

### Bloom filter lookups silently miss

**Symptom**: a domain you know is in the blacklist (verified server-side)
doesn't trigger any bloom hit on device.

**Cause**: signed vs unsigned modulo mismatch. Swift `BloomFilter.swift`
must use `pythonMod` (signed int32, Python-style). Native Swift `%` on
`UInt32` is unsigned and gives different bit positions.

**Fix**: read [CLAUDE.md](../CLAUDE.md) "Signed modulo". Run the
cross-validation tests in `backend/tests/test_cross_validation.py` against
the iOS ground-truth JSONs.

### Notification spam from invisible ad domains

**Symptom**: visiting a popular site (e.g., `yahoo.com`) triggers 10+
notifications for ad/tracker subdomains.

**Cause**: known historical bug — fixed. If it recurs:
- Verify notification suppression logic in iOS (rate limit, brand-only
  filter, 3-second resource window).
- Verify the offending domains are filtered at ingestion (Majestic Million
  top-100K filter in `backend/app/ingestion/runner.py`).

See [CHANGELOG.md](../CHANGELOG.md) April 7, 2026 entry for context.

### False notification for a legitimate brand domain

**Symptom**: e.g., `santander-mx.com` (legitimate Santander Mexico) triggers
"Sitio peligroso confirmado".

**Cause**: agent returned high confidence on a name-collision case. The
notification decision is now agent-owned via `should_notify`. If the agent
sets `should_notify=true` for a legitimate domain, the prompt criteria need
tightening (see `backend/app/investigation/graph.py`).

**Fix**:
1. Immediate: `/add-domain <domain>` to whitelist authoritatively.
2. Medium-term: refine the agent prompt rule for the failure pattern.

---

## CI and tests

### `pytest` fails locally for everyone but the agent tests

**Symptom**: `test_agent.py` flaky or fails on a clean checkout.

**Cause**: Bedrock mocks are sensitive to patch paths — patch where the
function is *used*, not where it's *defined*.

**Fix**: see `.claude/skills/test-backend.md` "Patching the wrong path".

### `RuntimeError: Event loop is closed` in pytest

**Symptom**: random failure in an async test.

**Cause**: mixing sync and async fixtures, or missing `asyncio_mode=auto`.

**Fix**: verify `backend/pytest.ini` has `asyncio_mode = auto`. Make the
fixture `async def` or use `pytest_asyncio`.

### `aioboto3` connection error in a test

**Symptom**: a test tries to hit real DynamoDB (`Connection refused`).

**Cause**: bypassed `mock_get_table` — the code path imports `get_table`
from a different module than the one you patched.

**Fix**: trace the import path. Patch `get_table` where it's looked up by
the code under test.

### CI is green but prod is broken

**Symptom**: tests pass on `main`, but deployed container is misbehaving.

**Cause**: **CI is broken** (missing `AWS_DEPLOY_ROLE_ARN`). A green "pushed
to main" does NOT mean "deployed". CI runs tests; it does not deploy.

**Fix**: run `/deploy-backend-fast` (or `/deploy` for infra changes) from
your laptop. See [ONBOARDING.md](../ONBOARDING.md) footguns.

### Tests pass locally, fail in CI (when CI is fixed)

**Symptom**: green locally, red in Actions.

**Cause**: implicit dependency on a file CI doesn't have (e.g., a CSV under
`ml/data/` you generated locally).

**Fix**: make the test self-contained. Use fixtures from `conftest.py` or
generate the data in the test.

---

## When you're really stuck

1. `/onboard-new-dev` — rule out local environment.
2. `/status` — health snapshot.
3. `/logs-backend errors` — most recent server-side issues.
4. Search [CLAUDE.md](../CLAUDE.md) (footguns) and
   [CHANGELOG.md](../CHANGELOG.md) (history — "why is this like this?").
5. Search [architecture.md](../architecture.md) — deepest reference.
6. Post in the team channel with: what you tried, the exact error, and the
   output of `/onboard-new-dev`.

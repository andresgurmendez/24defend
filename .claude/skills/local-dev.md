# /local-dev — Bring up the local stack

Run the backend + DynamoDB local in Docker, and open the iOS project in the
simulator. Use this as the day-to-day "start working" command.

## When to use

- Starting a coding session
- After a fresh clone, to validate the environment
- After pulling main, to make sure nothing in compose/Dockerfile broke

## Prerequisites

- Docker Desktop running
- `aws.sh` at repo root with valid dev IAM keys (account 081856108753)
- Xcode + `xcodegen` for the iOS side (`brew install xcodegen`)

## Usage

```
/local-dev               # start backend stack, do NOT open Xcode
/local-dev ios           # also regenerate xcodeproj and open Xcode
/local-dev fresh         # `--build` + recreate containers
```

## Commands — backend stack

```bash
cd /Users/mgurmendez/git/24defend-mono

# 1. AWS creds (Bedrock requires them even locally)
source aws.sh

# 2. Bring up api + dynamodb-local
cd backend
docker compose up --build -d

# 3. Verify
sleep 3
curl -s -m 3 -w "  HTTP %{http_code}\n" http://localhost:9147/health -o /dev/null
# Expect HTTP 200

# 4. Show docs URL and follow logs
echo ""
echo "API:        http://localhost:9147"
echo "Docs:       http://localhost:9147/docs"
echo "DynamoDB:   http://localhost:8000 (in-memory, resets on restart)"
echo ""
docker compose logs -f api
```

## Commands — iOS

```bash
cd /Users/mgurmendez/git/24defend-mono/ios
xcodegen generate

# Restore Info.plist tweaks that xcodegen overwrites (see /ios-build)
# NOTE: xcodegen overwrites these every time
# - TwentyFourDefend/Info.plist: restore CFBundleDisplayName
# - TwentyFourDefendPacketTunnel/Info.plist: restore NSExtension dict

open TwentyFourDefend.xcodeproj
# In Xcode: select "TwentyFourDefend" scheme, target iPhone 15 simulator, Cmd+R
```

NetworkExtension does NOT function in the iOS simulator. The UI runs; the
packet tunnel does not. Real-device testing requires Apple Developer
enrollment (see `ios/DISTRIBUTION.md`).

## Environment variables in compose

These are set in `backend/docker-compose.yml`. Override via shell env if needed:

| Var | Default | Purpose |
|-----|---------|---------|
| `DEFEND_API_KEY` | `dev-api-key-change-me` | Auth for /admin/* |
| `DEFEND_DYNAMODB_ENDPOINT` | `http://dynamodb-local:8000` | Local DDB |
| `DEFEND_BEDROCK_MODEL_ID` | claude sonnet 4.6 | Bedrock model |
| `AWS_ACCESS_KEY_ID` | from `aws.sh` | Required for Bedrock |
| `DEFEND_SERPER_API_KEY` | from `serper.conf` | Optional |

To override at runtime:
```bash
DEFEND_BEDROCK_MODEL_ID=us.anthropic.claude-haiku-... docker compose up
```

## Stop / clean

```bash
cd /Users/mgurmendez/git/24defend-mono/backend
docker compose down                # stop, keep volumes
docker compose down -v             # stop and wipe DynamoDB local data
```

## Verify it works end-to-end

```bash
# 1. Health
curl -s http://localhost:9147/health
# {"status":"ok"}

# 2. Add a known whitelist entry
curl -s -X POST http://localhost:9147/admin/domains \
  -H "X-Api-Key: dev-api-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{"domains":["brou.com.uy"],"entry_type":"whitelist","partner_id":"brou"}'

# 3. Check that domain
curl -s -X POST http://localhost:9147/check \
  -H "Content-Type: application/json" \
  -d '{"domain":"brou.com.uy"}'
# Expect: verdict=allow, source=whitelist
```

## Gotchas

### Port 9147 already in use
The `api` service maps host 9147 → container 8080. If something else owns 9147:
```bash
lsof -i :9147
# kill that process or edit backend/docker-compose.yml to use a different host port
```

### Port 8000 collides with another local DB
`dynamodb-local` listens on host port 8000. Common collision with other dev tools.
Either stop the other tool, or edit `backend/docker-compose.yml` to map e.g. `8765:8000`
AND update `DEFEND_DYNAMODB_ENDPOINT` accordingly inside compose.

### AWS creds expired / not loaded
Symptom: Bedrock calls return `ExpiredTokenException` or `UnrecognizedClientException`.
Fix: `source aws.sh` in the shell that ran `docker compose up`. Re-check creds:
```bash
aws sts get-caller-identity
# Expect Account: 081856108753
```
Compose reads env at start; restart the api container after re-sourcing:
```bash
docker compose up -d --force-recreate api
```

### DynamoDB data resets every restart
`dynamodb-local` uses `-inMemory`. Intentional. Don't expect cross-session persistence.
If you need a populated table for tests, run the seed script:
```bash
DEFEND_API_KEY=dev-api-key-change-me python3 scripts/seed_uruguay.py http://localhost:9147
```

### iOS NetworkExtension fails in simulator
Expected. The simulator can't actually install a VPN configuration. To exercise
the full pipeline, deploy to a real device — see `ios/DISTRIBUTION.md`.

### `xcodegen generate` blew away my Info.plist
Footgun. Use the `/ios-build` skill which encodes the restore steps. Or read
`CLAUDE.md` section "iOS project regeneration".

## Next step

Open `http://localhost:9147/docs` and exercise the API in the Swagger UI.
Then make a code change and watch `docker compose logs -f api` auto-reload
(uvicorn is started with `--reload` via the dev compose — verify if you don't
see reloads after editing).

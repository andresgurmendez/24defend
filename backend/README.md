# backend/

FastAPI service that backs the 24Defend iOS app. Holds the domain database, runs the agent investigation graph, serves bloom filters, and runs scheduled ingestion.

For system-level context (request flow, bloom filter design, agent prompt), see [`../architecture.md`](../architecture.md). For project-wide patterns and footguns, see [`../CLAUDE.md`](../CLAUDE.md).

## Stack

| Component | Version |
|-----------|---------|
| Python | 3.12 |
| FastAPI | 0.115.x |
| Pydantic | 2.x |
| DynamoDB (aioboto3) | 15.x |
| LangGraph | >= 0.4 |
| LangChain (Bedrock) | >= 0.3 |
| Scheduler | APScheduler 3.11 |
| Bloom filter | mmh3 + bitarray |

Bedrock model: `us.anthropic.claude-sonnet-4-6` (see `docker-compose.yml`).

## Directory layout

```
backend/
├── app/
│   ├── main.py                   # FastAPI app + lifespan
│   ├── config.py                 # Pydantic settings (DEFEND_* env vars)
│   ├── auth.py                   # X-Api-Key dependency
│   ├── db.py                     # DynamoDB session / ensure_table
│   ├── domain_service.py         # CRUD on the domains table
│   ├── models.py                 # Pydantic models (DomainEntry, request/response)
│   ├── agent.py                  # Whitelist cache + helpers
│   ├── bloom.py                  # Bloom filter generation
│   ├── scheduler.py              # APScheduler jobs (daily ingest, bloom regen)
│   ├── routes/
│   │   ├── check.py              # POST /check — main client endpoint
│   │   ├── admin.py              # /admin/* + public /daily-* endpoints
│   │   └── telemetry.py          # Anonymous device telemetry
│   ├── investigation/
│   │   ├── graph.py              # LangGraph agent (system prompt lives here)
│   │   └── tools.py              # Agent tools (Safe Browsing, RDAP, Serper, ...)
│   └── ingestion/
│       ├── runner.py             # Orchestrator + Majestic Million filter
│       └── sources.py            # Per-feed fetchers
├── tests/                        # 160+ pytest tests
├── scripts/seed_uruguay.py       # One-shot seed for UY whitelist
├── docker-compose.yml            # api + dynamodb-local
├── Dockerfile                    # FROM --platform=linux/amd64 python:3.12-slim
├── requirements.txt
└── requirements-test.txt
```

## Run locally

Easiest path is the `/local-dev` skill. Manually:

```bash
source ../aws.sh                  # Bedrock creds (read-only IAM keys for dev account)
docker compose up --build
# API:  http://localhost:9147
# Docs: http://localhost:9147/docs
# Local DynamoDB on http://localhost:8000 (in-memory, resets every restart)
```

Without Docker (faster iteration on Python code):

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-test.txt
source ../aws.sh
DEFEND_DYNAMODB_ENDPOINT=http://localhost:8000 \
DEFEND_API_KEY=dev-api-key-change-me \
.venv/bin/uvicorn app.main:app --reload --port 9147
```

You still need DynamoDB local for this — easiest is `docker compose up dynamodb-local`.

## Run tests

```bash
.venv/bin/python -m pytest tests/ -v
```

Tests do not hit AWS. DynamoDB is mocked via a dict-backed `FakeTable` in `tests/conftest.py`; Bedrock is patched per-test. Expect 160+ green in under 30s.

See `/test-backend` for patterns (single test, debugging, writing a new test, fixtures).

## Add a new endpoint

1. Decide which router: `routes/check.py` (device-facing, no auth), `routes/admin.py` (privileged, `X-Api-Key`), `routes/telemetry.py` (anonymous device telemetry), or a new file (then register it in `main.py`).
2. Define Pydantic request/response models in `app/models.py`. Keep field names snake_case; the iOS client mirrors them.
3. Implement the handler. Async-await all the way down — `aioboto3` is awaited, `httpx.AsyncClient` is awaited.
4. Add a test in `tests/` using the `client` fixture from `conftest.py`. For protected endpoints, use the `admin_headers` fixture.
5. If the endpoint is supposed to be reachable from the iOS app, also update `ios/Shared/APIClient.swift` and add a Swift model.
6. Update `architecture.md` if the endpoint changes the request flow.

## Add a tool to the investigation agent

1. Implement an async function in `app/investigation/tools.py` decorated with `@tool` (LangChain).
2. Register it in the tool list inside `app/investigation/graph.py`.
3. Update the system prompt in `graph.py` to teach the agent when to call the tool (and, critically, when *not* to — over-eager tool use produces false positives).
4. Add an integration test in `tests/test_agent.py` mocking the tool output and asserting the verdict.
5. Document the tool in `architecture.md` under the agent section.

The current tool set: `safe_browsing_check`, `rdap_lookup`, `serper_search`, heuristics tool, whitelist tool. Read the existing definitions in `tools.py` before adding new ones — there's a pattern for handling missing API keys (explicit "do NOT treat as a flag" rather than silently assuming a hit).

## Add a field to a Pydantic model

1. Add the field with a default in `app/models.py`.
2. Update any test fixtures in `tests/conftest.py` (e.g. `seeded_store`).
3. Update the iOS Swift model in `ios/Shared/` to keep parity. Devices on older builds will ignore unknown fields, but adding a *required* field without a default breaks them — always default new fields.
4. If the field is persisted to DynamoDB, double-check the cache TTL — old cache entries won't have it on read.

## Local environment variables

Defaults are in `app/config.py` (Pydantic `Settings`). Override via env vars or the `docker-compose.yml`.

| Var | Default | Purpose |
|-----|---------|---------|
| `DEFEND_API_KEY` | `dev-api-key-change-me` | `X-Api-Key` for `/admin/*` |
| `DEFEND_DYNAMODB_ENDPOINT` | unset (= real DynamoDB) | Set for local: `http://dynamodb-local:8000` |
| `DEFEND_BEDROCK_MODEL_ID` | claude sonnet 4.6 (id in compose) | Pin the model |
| `DEFEND_SAFE_BROWSING_API_KEY` | unset | Optional. Without it, Safe Browsing tool tells the agent "do NOT treat as a flag" |
| `DEFEND_SERPER_API_KEY` | unset | Optional. Enables Google search tool |
| `DEFEND_ENV` | `dev` | Used as a tag for telemetry / logs |

## Deploy

- **Code-only**: `/deploy-backend-fast` (~2 min)
- **Infrastructure change**: `/deploy` (~5 min, runs CDK)
- See [`../CLAUDE.md`](../CLAUDE.md#deployment-patterns) for the rationale

## What to read next

- `architecture.md` (root) — full system + request flow
- `research/improvements.md` — backlog
- `tests/conftest.py` — testing patterns and fixtures
- `app/investigation/graph.py` — agent system prompt (it's the most-tuned piece in the codebase)

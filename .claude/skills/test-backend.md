# /test-backend — Run pytest for the backend

Run the backend test suite, a single test, or write a new one. Tests are
fast (160+ in under 30s) because DynamoDB and Bedrock are mocked in-process.

## When to use

- Before opening a PR
- After modifying anything in `backend/app/`
- After updating `requirements.txt` (verify imports still work)
- When debugging — write a failing test before the fix

## Prerequisites

- Backend venv created:
  ```bash
  cd /Users/mgurmendez/git/24defend-mono/backend
  python3.12 -m venv .venv
  .venv/bin/pip install -r requirements.txt -r requirements-test.txt
  ```
- No AWS creds needed — tests don't hit AWS.

## Usage

```
/test-backend                        # full suite
/test-backend <pattern>              # single test or file by substring
/test-backend cov                    # with coverage report
/test-backend -k "check and not bloom"   # pytest keyword filter
```

## Commands

```bash
cd /Users/mgurmendez/git/24defend-mono/backend

# Full suite (default)
.venv/bin/python -m pytest tests/ -v

# Single file
.venv/bin/python -m pytest tests/test_check.py -v

# Single test by name
.venv/bin/python -m pytest tests/test_check.py::test_known_blacklist_blocks -v

# Pattern
.venv/bin/python -m pytest tests/ -v -k "bloom"

# Stop on first failure (useful when iterating)
.venv/bin/python -m pytest tests/ -x

# Coverage (requires pytest-cov in requirements-test.txt)
.venv/bin/python -m pytest tests/ --cov=app --cov-report=term-missing
```

## Test layout

```
backend/tests/
├── conftest.py              # FakeTable (dict-backed DynamoDB), test_app, client fixtures
├── test_check.py            # POST /check — blacklist / whitelist / cache / agent paths
├── test_admin.py            # /admin/* endpoints (auth, bulk add, ingest, bloom)
├── test_agent.py            # LangGraph agent: verdict parsing, tool routing, fallbacks
├── test_bloom.py            # Bloom filter build / signed mod / serialization
├── test_ingestion.py        # Per-feed parsing (PhishTank, OpenPhish, URLhaus, Phishing.Army)
└── test_cross_validation.py # Agreement vs iOS ground-truth fixtures (mmh3 / features)
```

`pytest.ini` sets `asyncio_mode = auto`, so async tests don't need decorators.

## DynamoDB mock — how it works

`conftest.py` provides `FakeTable`, a dict-backed mimic of an aioboto3 DynamoDB
Table. It supports `get_item`, `put_item`, `delete_item`, `scan` (with simple
filter-expression handling), and `batch_writer`. No moto, no localstack.

```python
from app.domain_service import lookup_domain, put_domain

async def test_lookup_existing(mock_get_table, seeded_store):
    entry = await lookup_domain("evil-phish.com")
    assert entry is not None
    assert entry.entry_type.value == "blacklist"
```

Fixtures available:
| Fixture | What it gives you |
|---------|-------------------|
| `domain_store` | Empty dict for the in-memory table |
| `fake_table` | A `FakeTable` backed by `domain_store` |
| `mock_get_table` | Patches `app.domain_service.get_table` to return `fake_table` |
| `seeded_store` | Pre-populated with a blacklist, whitelist, and cache entry |
| `test_app` | FastAPI app with routers wired in, no lifespan |
| `client` | `httpx.AsyncClient` against `test_app` |
| `admin_headers` | `{"x-api-key": "dev-api-key-change-me"}` |

## Bedrock / agent mock

`test_agent.py` patches the LangChain Bedrock LLM constructor to return a
fake that emits a canned message. Pattern:

```python
from unittest.mock import patch, AsyncMock, MagicMock

@patch("app.investigation.graph._create_llm")
async def test_agent_returns_block(mock_llm):
    fake = MagicMock()
    fake.ainvoke = AsyncMock(return_value=MagicMock(content="VERDICT: block\nCONFIDENCE: 0.92\n..."))
    fake.bind_tools = MagicMock(return_value=fake)
    mock_llm.return_value = fake
    ...
```

Real Bedrock costs money and is non-deterministic. Always mock it in tests.

## Writing a new test

1. Pick the right file by what's under test (`test_check.py` for routes,
   `test_agent.py` for the LangGraph graph, etc.).
2. Use the highest-level fixture that gets the job done: prefer `client`
   over driving the service directly.
3. Use `seeded_store` if you need pre-existing domains.
4. For new external dependencies (a new tool, a new feed source), mock the
   network call with `httpx.MockTransport` or `unittest.mock.patch`.
5. Assert what matters: the HTTP status, the response body shape, side
   effects in `domain_store`. Don't assert on log strings.

Template:

```python
async def test_check_unknown_domain_runs_agent(client, mock_get_table):
    # Arrange: store is empty, agent will be called
    with patch("app.routes.check.investigate_domain") as mock_invest:
        mock_invest.return_value = MagicMock(
            verdict="warn", confidence=0.7, reason="suspicious", should_notify=False
        )

        # Act
        r = await client.post("/check", json={"domain": "weird-thing.xyz"})

        # Assert
        assert r.status_code == 200
        body = r.json()
        assert body["verdict"] == "warn"
        assert body["source"] == "agent"
```

## Coverage status

160+ tests. Coverage is high on routes (`check.py`, `admin.py`) and bloom
logic. The LangGraph agent has tighter coverage on the verdict parser and
fallback path; tool internals are mostly mocked. If you're adding a new tool
or a new branch in the agent graph, add tests there.

## Gotchas

### `RuntimeError: Event loop is closed`
Usually means you mixed sync `pytest` fixtures with async ones or didn't use
`asyncio_mode=auto`. Verify `pytest.ini` and that the fixture is `async def`
or `yield`-based as needed.

### Patching the wrong path
`patch("app.routes.check.investigate_domain")` patches *the import inside that
module*, not `app.investigation.graph.investigate_domain`. Always patch the
binding where it's *used*, not where it's *defined*.

### Tests pass locally but fail in CI
CI is broken right now (missing `AWS_DEPLOY_ROLE_ARN`). When CI comes back,
the most common cause of locally-green / CI-red is implicit dependency on a
shared file (e.g., a CSV in `ml/data/` that you have but CI doesn't). Keep
tests self-contained.

### `aioboto3` connection error during a test
You bypassed `mock_get_table` somewhere. Trace where the call ends up — likely
a code path that imports `get_table` from a different module than the one you
patched.

## Next step

Run the full suite, watch what's green, then `git diff` your change and find
something with no coverage. Add a test.

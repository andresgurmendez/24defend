"""Shared fixtures for 24Defend backend tests.

Provides:
- In-memory DynamoDB mock (dict-based, no external dependencies)
- FastAPI test client with mocked DB
- API key header helper
"""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from fastapi import FastAPI

from app.models import DomainEntry, EntryType, Verdict
from app.routes.check import router as check_router
from app.routes.admin import router as admin_router, public_router as admin_public_router


# ---------------------------------------------------------------------------
# In-memory DynamoDB mock
# ---------------------------------------------------------------------------

class FakeBatchWriter:
    """Mimics DynamoDB batch_writer context manager."""

    def __init__(self, store: dict):
        self._store = store

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def put_item(self, Item: dict):
        key = Item["domain"]
        self._store[key] = dict(Item)


class FakeTable:
    """Dict-backed mock of an aioboto3 DynamoDB Table resource."""

    def __init__(self, store: dict):
        self._store = store

    async def get_item(self, Key: dict) -> dict:
        domain = Key["domain"]
        item = self._store.get(domain)
        if item:
            return {"Item": item}
        return {}

    async def put_item(self, Item: dict):
        key = Item["domain"]
        self._store[key] = dict(Item)

    async def delete_item(self, Key: dict):
        domain = Key["domain"]
        self._store.pop(domain, None)

    async def scan(self, **kwargs) -> dict:
        filter_expr = kwargs.get("FilterExpression", "")
        attr_values = kwargs.get("ExpressionAttributeValues", {})

        items = []
        for item in self._store.values():
            match = True
            if ":t" in attr_values:
                if item.get("entry_type") != attr_values[":t"]:
                    match = False
            if ":p" in attr_values:
                if item.get("partner_id") != attr_values[":p"]:
                    match = False
            if match:
                items.append(item)

        return {"Items": items}

    def batch_writer(self):
        return FakeBatchWriter(self._store)


@pytest.fixture
def domain_store():
    """Fresh in-memory domain store for each test."""
    return {}


@pytest.fixture
def fake_table(domain_store):
    """FakeTable backed by the domain_store fixture."""
    return FakeTable(domain_store)


@pytest.fixture
def mock_get_table(fake_table):
    """Patch app.db.get_table to return our FakeTable."""

    @asynccontextmanager
    async def _mock():
        yield fake_table

    with patch("app.domain_service.get_table", _mock):
        yield fake_table


@pytest.fixture
def seeded_store(domain_store):
    """Pre-populate the store with some test data."""
    domain_store["evil-phish.com"] = {
        "domain": "evil-phish.com",
        "entry_type": "blacklist",
        "reason": "Known phishing",
    }
    domain_store["brou.com.uy"] = {
        "domain": "brou.com.uy",
        "entry_type": "whitelist",
        "partner_id": "brou",
    }
    domain_store["cached-domain.com"] = {
        "domain": "cached-domain.com",
        "entry_type": "cache",
        "verdict": "warn",
        "confidence": "0.6",
        "reason": "Previously investigated",
    }
    return domain_store


# ---------------------------------------------------------------------------
# FastAPI test app + httpx AsyncClient
# ---------------------------------------------------------------------------

def _build_test_app() -> FastAPI:
    """Build a minimal FastAPI app with just the routers (no lifespan)."""
    test_app = FastAPI()
    test_app.include_router(check_router)
    test_app.include_router(admin_router)
    test_app.include_router(admin_public_router)

    @test_app.get("/health")
    async def health():
        return {"status": "ok"}

    return test_app


@pytest.fixture
def test_app():
    return _build_test_app()


@pytest.fixture
async def client(test_app):
    """httpx.AsyncClient wired to the test FastAPI app."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url="http://test",
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

API_KEY = "dev-api-key-change-me"


@pytest.fixture
def admin_headers():
    """Headers dict with the default dev API key."""
    return {"x-api-key": API_KEY}

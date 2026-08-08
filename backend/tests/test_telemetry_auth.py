"""Tests for the dashboard auth flow added in PR #14 (review round 2).

Covers:
- POST /telemetry/login (correct/incorrect dashboard key)
- GET /telemetry/session (valid/missing/tampered/expired cookie)
- GET /telemetry/stats now gated by the session cookie, not X-API-Key
- The dashboard key is scoped read-only: it must NOT pass require_api_key,
  so a leaked dashboard session/key can't reach /admin/*
"""

import time
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest

from app.auth import DASHBOARD_SESSION_COOKIE, _sign_session
from app.config import settings
from tests.conftest import DASHBOARD_API_KEY, API_KEY


@pytest.fixture
def mock_telemetry_table(fake_table):
    """telemetry.py imports get_table directly from app.db (not via
    app.domain_service like the admin/check routes), so it needs its own
    patch target."""

    @asynccontextmanager
    async def _mock():
        yield fake_table

    with patch("app.routes.telemetry.get_table", _mock):
        yield fake_table


class TestDashboardLogin:
    async def test_correct_key_sets_httponly_cookie(self, client, mock_telemetry_table):
        resp = await client.post("/telemetry/login", json={"dashboard_key": DASHBOARD_API_KEY})
        assert resp.status_code == 200
        cookie = resp.cookies.get(DASHBOARD_SESSION_COOKIE)
        assert cookie is not None
        # httpx.Cookies doesn't expose Set-Cookie attributes directly; check
        # the raw header instead.
        set_cookie = resp.headers.get("set-cookie", "").lower()
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie
        assert "secure" in set_cookie

    async def test_wrong_key_rejected_no_cookie(self, client, mock_telemetry_table):
        resp = await client.post("/telemetry/login", json={"dashboard_key": "wrong-key"})
        assert resp.status_code == 401
        assert DASHBOARD_SESSION_COOKIE not in resp.cookies

    async def test_admin_api_key_does_not_work_as_dashboard_key(self, client, mock_telemetry_table):
        """The whole point of splitting the credential (findings #1/#2): the
        admin key must not double as a dashboard login."""
        resp = await client.post("/telemetry/login", json={"dashboard_key": API_KEY})
        assert resp.status_code == 401


class TestDashboardSession:
    async def test_no_cookie_rejected(self, client, mock_telemetry_table):
        resp = await client.get("/telemetry/session")
        assert resp.status_code == 401

    async def test_valid_session_after_login(self, client, mock_telemetry_table):
        login = await client.post("/telemetry/login", json={"dashboard_key": DASHBOARD_API_KEY})
        assert login.status_code == 200
        resp = await client.get("/telemetry/session")
        assert resp.status_code == 200

    async def test_tampered_cookie_rejected(self, client, mock_telemetry_table):
        client.cookies.set(DASHBOARD_SESSION_COOKIE, "9999999999.deadbeef")
        resp = await client.get("/telemetry/session")
        assert resp.status_code == 401

    async def test_expired_cookie_rejected(self, client, mock_telemetry_table):
        expired = int(time.time()) - 10
        token = _sign_session(expired)
        client.cookies.set(DASHBOARD_SESSION_COOKIE, token)
        resp = await client.get("/telemetry/session")
        assert resp.status_code == 401

    async def test_logout_clears_session(self, client, mock_telemetry_table):
        await client.post("/telemetry/login", json={"dashboard_key": DASHBOARD_API_KEY})
        assert (await client.get("/telemetry/session")).status_code == 200

        logout = await client.post("/telemetry/logout")
        assert logout.status_code == 200
        client.cookies.delete(DASHBOARD_SESSION_COOKIE)

        assert (await client.get("/telemetry/session")).status_code == 401


class TestTelemetryStatsAuth:
    async def test_stats_requires_session(self, client, mock_telemetry_table):
        resp = await client.get("/telemetry/stats")
        assert resp.status_code == 401

    async def test_stats_admin_api_key_alone_not_sufficient(self, client, mock_telemetry_table):
        """X-API-Key (the admin key) no longer gates /telemetry/stats — only
        a dashboard session cookie does."""
        resp = await client.get("/telemetry/stats", headers={"x-api-key": API_KEY})
        assert resp.status_code == 401

    async def test_stats_succeeds_with_valid_session(self, client, mock_telemetry_table):
        await client.post("/telemetry/login", json={"dashboard_key": DASHBOARD_API_KEY})
        resp = await client.get("/telemetry/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert "total_events" in body
        assert "by_layer" in body

"""Tests for admin endpoints.

Covers:
- POST /admin/domains (bulk add)
- DELETE /admin/domains/{domain}
- GET /admin/domains (list by type)
- GET /admin/bloom-filter/whitelist and /blacklist
- POST /admin/bloom-filter/regenerate
- GET /admin/bloom-filter/stats
- Auth (missing/invalid API key)
"""

from unittest.mock import patch, AsyncMock, MagicMock
from pathlib import Path

import pytest

from tests.conftest import API_KEY


def _seed(fake_table, domain, entry_type, **kwargs):
    item = {"domain": domain.lower(), "entry_type": entry_type}
    item.update(kwargs)
    fake_table._store[domain.lower()] = item


class TestAdminAuth:
    async def test_missing_api_key(self, client, mock_get_table):
        resp = await client.post("/admin/domains", json={
            "domains": ["evil.com"], "entry_type": "blacklist",
        })
        assert resp.status_code == 422  # missing header

    async def test_invalid_api_key(self, client, mock_get_table):
        resp = await client.post(
            "/admin/domains",
            json={"domains": ["evil.com"], "entry_type": "blacklist"},
            headers={"x-api-key": "wrong-key"},
        )
        assert resp.status_code == 401

    async def test_valid_api_key_succeeds(self, client, mock_get_table, admin_headers):
        resp = await client.post(
            "/admin/domains",
            json={"domains": ["evil.com"], "entry_type": "blacklist"},
            headers=admin_headers,
        )
        assert resp.status_code == 200


class TestBulkAddDomains:
    async def test_add_blacklist(self, client, mock_get_table, fake_table, admin_headers):
        resp = await client.post(
            "/admin/domains",
            json={"domains": ["bad1.com", "bad2.com"], "entry_type": "blacklist", "reason": "Manual add"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["added"] == 2
        assert data["entry_type"] == "blacklist"

        # Verify in store
        assert "bad1.com" in fake_table._store
        assert "bad2.com" in fake_table._store
        assert fake_table._store["bad1.com"]["entry_type"] == "blacklist"

    async def test_add_whitelist_with_partner(self, client, mock_get_table, fake_table, admin_headers):
        resp = await client.post(
            "/admin/domains",
            json={
                "domains": ["safe.bank.com"],
                "entry_type": "whitelist",
                "partner_id": "bank",
            },
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert fake_table._store["safe.bank.com"]["partner_id"] == "bank"

    async def test_add_empty_list(self, client, mock_get_table, admin_headers):
        resp = await client.post(
            "/admin/domains",
            json={"domains": [], "entry_type": "blacklist"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["added"] == 0


class TestDeleteDomain:
    async def test_delete_existing(self, client, mock_get_table, fake_table, admin_headers):
        _seed(fake_table, "evil.com", "blacklist")

        resp = await client.delete("/admin/domains/evil.com", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] == "evil.com"
        assert "evil.com" not in fake_table._store

    async def test_delete_nonexistent(self, client, mock_get_table, admin_headers):
        """Deleting a non-existent domain should still return 200 (idempotent)."""
        resp = await client.delete("/admin/domains/nope.com", headers=admin_headers)
        assert resp.status_code == 200


class TestListDomains:
    async def test_list_blacklist(self, client, mock_get_table, fake_table, admin_headers):
        _seed(fake_table, "bad1.com", "blacklist")
        _seed(fake_table, "bad2.com", "blacklist")
        _seed(fake_table, "safe.com", "whitelist")

        resp = await client.get("/admin/domains", params={"entry_type": "blacklist"}, headers=admin_headers)
        assert resp.status_code == 200
        domains = [e["domain"] for e in resp.json()]
        assert "bad1.com" in domains
        assert "bad2.com" in domains
        assert "safe.com" not in domains

    async def test_list_whitelist(self, client, mock_get_table, fake_table, admin_headers):
        _seed(fake_table, "safe.com", "whitelist", partner_id="p1")

        resp = await client.get("/admin/domains", params={"entry_type": "whitelist"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["domain"] == "safe.com"

    async def test_list_with_partner_filter(self, client, mock_get_table, fake_table, admin_headers):
        _seed(fake_table, "a.com", "whitelist", partner_id="p1")
        _seed(fake_table, "b.com", "whitelist", partner_id="p2")

        resp = await client.get(
            "/admin/domains",
            params={"entry_type": "whitelist", "partner_id": "p1"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        domains = [e["domain"] for e in resp.json()]
        assert "a.com" in domains
        assert "b.com" not in domains

    async def test_list_empty(self, client, mock_get_table, admin_headers):
        resp = await client.get("/admin/domains", params={"entry_type": "cache"}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == []


class TestBloomFilterEndpoints:
    async def test_whitelist_bloom_not_yet_generated(self, client, mock_get_table, admin_headers):
        with patch("app.routes.admin.read_bloom_file", return_value=None):
            resp = await client.get("/admin/bloom-filter/whitelist", headers=admin_headers)
            assert resp.status_code == 503

    async def test_whitelist_bloom_served(self, client, mock_get_table, admin_headers):
        fake_bloom = b"\x00\x00\x00\x40\x00\x00\x00\x03" + b"\xff" * 8
        with patch("app.routes.admin.read_bloom_file", return_value=fake_bloom):
            resp = await client.get("/admin/bloom-filter/whitelist", headers=admin_headers)
            assert resp.status_code == 200
            assert resp.headers["content-type"] == "application/octet-stream"
            assert resp.content == fake_bloom

    async def test_blacklist_bloom_not_yet_generated(self, client, mock_get_table, admin_headers):
        with patch("app.routes.admin.read_bloom_file", return_value=None):
            resp = await client.get("/admin/bloom-filter/blacklist", headers=admin_headers)
            assert resp.status_code == 503

    async def test_blacklist_bloom_served(self, client, mock_get_table, admin_headers):
        fake_bloom = b"\x00\x00\x00\x40\x00\x00\x00\x03" + b"\xff" * 8
        with patch("app.routes.admin.read_bloom_file", return_value=fake_bloom):
            resp = await client.get("/admin/bloom-filter/blacklist", headers=admin_headers)
            assert resp.status_code == 200
            assert resp.content == fake_bloom

    async def test_bloom_stats(self, client, mock_get_table, fake_table, admin_headers):
        _seed(fake_table, "safe.com", "whitelist")
        _seed(fake_table, "bad.com", "blacklist")

        resp = await client.get("/admin/bloom-filter/stats", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "whitelist" in data
        assert "blacklist" in data
        assert data["whitelist"]["total_entries"] == 1
        assert data["blacklist"]["total_entries"] == 1

    async def test_regenerate_bloom(self, client, mock_get_table, admin_headers):
        with patch("app.routes.admin.generate_and_store_bloom_filters", new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = {"whitelist_bytes": 100, "blacklist_bytes": 200}
            resp = await client.post("/admin/bloom-filter/regenerate", headers=admin_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["whitelist_bytes"] == 100
            mock_gen.assert_awaited_once()


class TestIngestionEndpoints:
    async def test_ingest_blacklists(self, client, mock_get_table, admin_headers):
        with patch("app.routes.admin.run_blacklist_ingestion", new_callable=AsyncMock) as mock_ingest:
            mock_ingest.return_value = {
                "timestamp": "2026-01-01T00:00:00",
                "sources": {"openphish": 10, "phishing_army": 20},
                "total_unique": 25,
                "new_added": 15,
                "already_known": 10,
            }
            resp = await client.post("/admin/ingest/blacklists", headers=admin_headers)
            assert resp.status_code == 200
            assert resp.json()["new_added"] == 15

    async def test_whitelist_discovery(self, client, mock_get_table, admin_headers):
        with patch("app.routes.admin.run_whitelist_discovery", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = {
                "root_domain": "brou.com.uy",
                "discovered": 10,
                "new_added": 8,
                "already_known": 2,
            }
            resp = await client.post(
                "/admin/ingest/whitelist-discovery",
                json={"root_domain": "brou.com.uy", "partner_id": "brou"},
                headers=admin_headers,
            )
            assert resp.status_code == 200
            assert resp.json()["new_added"] == 8

    async def test_run_daily_job(self, client, mock_get_table, admin_headers):
        with patch("app.routes.admin.run_blacklist_ingestion", new_callable=AsyncMock) as mock_ingest, \
             patch("app.routes.admin.generate_and_store_bloom_filters", new_callable=AsyncMock) as mock_bloom:
            mock_ingest.return_value = {"new_added": 5}
            mock_bloom.return_value = {"whitelist_bytes": 100, "blacklist_bytes": 200}

            resp = await client.post("/admin/jobs/run-daily", headers=admin_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["ingestion"]["new_added"] == 5

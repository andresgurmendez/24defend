"""Tests for the POST /check endpoint.

Covers:
- Blacklist hit (instant block)
- Whitelist hit (instant allow)
- Cache hit (return cached verdict)
- Agent investigation (unknown domain)
- www. stripping
- Parent domain lookup (sub.evil.com -> evil.com)
"""

from unittest.mock import patch, AsyncMock

import pytest

from app.models import DomainEntry, EntryType, Verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_domain(fake_table, domain, entry_type, **kwargs):
    """Synchronous-friendly seeder for the fake table store."""
    item = {"domain": domain.lower(), "entry_type": entry_type}
    item.update(kwargs)
    fake_table._store[domain.lower()] = item


# ---------------------------------------------------------------------------
# /check endpoint tests
# ---------------------------------------------------------------------------

class TestCheckEndpoint:

    async def test_blacklist_hit(self, client, mock_get_table, fake_table):
        _seed_domain(fake_table, "evil-phish.com", "blacklist", reason="Known phishing")

        resp = await client.post("/check", json={"domain": "evil-phish.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "block"
        assert data["source"] == "blacklist"
        assert data["confidence"] == 1.0

    async def test_whitelist_hit(self, client, mock_get_table, fake_table):
        _seed_domain(fake_table, "brou.com.uy", "whitelist", partner_id="brou")

        resp = await client.post("/check", json={"domain": "brou.com.uy"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "allow"
        assert data["source"] == "whitelist"
        assert data["confidence"] == 1.0
        assert "brou" in data["reason"]

    async def test_cache_hit(self, client, mock_get_table, fake_table):
        _seed_domain(
            fake_table, "cached.com", "cache",
            verdict="warn", confidence="0.6", reason="Previously investigated",
        )

        resp = await client.post("/check", json={"domain": "cached.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "warn"
        assert data["source"] == "cache"
        assert data["confidence"] == 0.6

    async def test_www_stripping(self, client, mock_get_table, fake_table):
        """www.evil.com should match evil.com in the blacklist."""
        _seed_domain(fake_table, "evil.com", "blacklist", reason="Bad")

        resp = await client.post("/check", json={"domain": "www.evil.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "block"
        assert data["source"] == "blacklist"

    async def test_parent_domain_lookup(self, client, mock_get_table, fake_table):
        """sub.evil.com should match parent evil.com in the blacklist."""
        _seed_domain(fake_table, "evil.com", "blacklist", reason="Bad parent")

        resp = await client.post("/check", json={"domain": "sub.evil.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "block"
        assert data["source"] == "blacklist"

    async def test_deep_subdomain_lookup(self, client, mock_get_table, fake_table):
        """a.b.evil.com should walk up and find evil.com."""
        _seed_domain(fake_table, "evil.com", "blacklist", reason="Bad")

        resp = await client.post("/check", json={"domain": "a.b.evil.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "block"

    async def test_unknown_domain_triggers_agent(self, client, mock_get_table):
        """Domain not in DB should trigger the investigation agent."""
        mock_entry = DomainEntry(
            domain="unknown-site.com",
            entry_type=EntryType.cache,
            verdict=Verdict.allow,
            confidence=0.2,
            reason="Looks safe after investigation",
        )

        with patch("app.routes.check.investigate_domain", new_callable=AsyncMock) as mock_investigate:
            mock_investigate.return_value = mock_entry

            resp = await client.post("/check", json={"domain": "unknown-site.com"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["verdict"] == "allow"
            assert data["source"] == "agent"
            mock_investigate.assert_awaited_once_with("unknown-site.com")

    async def test_domain_normalized_to_lowercase(self, client, mock_get_table, fake_table):
        _seed_domain(fake_table, "evil.com", "blacklist", reason="Bad")

        resp = await client.post("/check", json={"domain": "EVIL.COM"})
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "block"

    async def test_trailing_dot_stripped(self, client, mock_get_table, fake_table):
        _seed_domain(fake_table, "evil.com", "blacklist", reason="Bad")

        resp = await client.post("/check", json={"domain": "evil.com."})
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "block"

    async def test_agent_block_verdict(self, client, mock_get_table):
        """Agent returning block verdict should be propagated."""
        mock_entry = DomainEntry(
            domain="phishy.xyz",
            entry_type=EntryType.cache,
            verdict=Verdict.block,
            confidence=0.9,
            reason="Multiple risk signals",
        )

        with patch("app.routes.check.investigate_domain", new_callable=AsyncMock) as mock_investigate:
            mock_investigate.return_value = mock_entry

            resp = await client.post("/check", json={"domain": "phishy.xyz"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["verdict"] == "block"
            assert data["source"] == "agent"
            assert data["confidence"] == 0.9

    async def test_missing_domain_field(self, client, mock_get_table):
        """Request without domain field should return 422."""
        resp = await client.post("/check", json={})
        assert resp.status_code == 422

    async def test_whitelist_partner_in_reason(self, client, mock_get_table, fake_table):
        _seed_domain(fake_table, "partner.com", "whitelist", partner_id="acme-corp")

        resp = await client.post("/check", json={"domain": "partner.com"})
        data = resp.json()
        assert "acme-corp" in data["reason"]

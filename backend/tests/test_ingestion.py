"""Tests for ingestion sources and runner.

Covers:
- Domain extraction from URLs (_extract_domain)
- Individual feed parsers (mocked HTTP responses)
- fetch_all_blacklists aggregation
- Deduplication in run_blacklist_ingestion
- Whitelist discovery via crt.sh
"""

from unittest.mock import patch, AsyncMock, MagicMock

import pytest
import httpx

from app.ingestion.sources import (
    _extract_domain,
    fetch_openphish,
    fetch_phishing_army,
    fetch_urlhaus,
    fetch_phishtank,
    fetch_crtsh_subdomains,
    fetch_all_blacklists,
)
from app.ingestion.runner import run_blacklist_ingestion, run_whitelist_discovery


# ---------------------------------------------------------------------------
# _extract_domain
# ---------------------------------------------------------------------------

class TestExtractDomain:
    def test_https_url(self):
        assert _extract_domain("https://evil.com/path") == "evil.com"

    def test_http_url(self):
        assert _extract_domain("http://phish.xyz/login") == "phish.xyz"

    def test_url_with_port(self):
        assert _extract_domain("https://evil.com:8443/path") == "evil.com"

    def test_url_with_query(self):
        assert _extract_domain("https://evil.com/path?q=1") == "evil.com"

    def test_url_with_fragment(self):
        assert _extract_domain("https://evil.com/path#frag") == "evil.com"

    def test_bare_domain(self):
        assert _extract_domain("evil.com") == "evil.com"

    def test_double_slash_prefix(self):
        assert _extract_domain("//evil.com/path") == "evil.com"

    def test_empty_string(self):
        assert _extract_domain("") is None

    def test_no_dot(self):
        assert _extract_domain("localhost") is None

    def test_uppercase_domain_in_url(self):
        """Domain part is lowercased; protocol must be lowercase for stripping."""
        assert _extract_domain("https://EVIL.COM/PATH") == "evil.com"

    def test_uppercase_protocol_not_stripped(self):
        """BUG NOTE: _extract_domain doesn't handle uppercase protocols.
        The prefix check is case-sensitive, so 'HTTPS://' is not stripped.
        This test documents the current behavior.
        """
        # With uppercase protocol, the function treats the whole thing as a domain
        # and fails the '.' check on the malformed result, returning None.
        result = _extract_domain("HTTPS://EVIL.COM/PATH")
        # Current behavior: returns None because protocol isn't stripped
        # If the bug is fixed, this should return "evil.com"
        assert result is None

    def test_trailing_dot(self):
        assert _extract_domain("https://evil.com./path") == "evil.com"

    def test_subdomain_preserved(self):
        assert _extract_domain("https://sub.evil.com/path") == "sub.evil.com"


# ---------------------------------------------------------------------------
# Feed parsers (mocked HTTP)
# ---------------------------------------------------------------------------

def _mock_httpx_client(response_text, status_code=200):
    """Create a mock httpx.AsyncClient that returns the given response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = response_text
    mock_resp.json.return_value = None  # override per test if needed

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestFetchOpenPhish:
    async def test_parse_feed(self):
        feed = "https://evil1.com/login\nhttps://evil2.com/phish\nhttps://evil1.com/other\n"
        mock_client = _mock_httpx_client(feed)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_openphish()
            assert "evil1.com" in domains
            assert "evil2.com" in domains
            # Deduplication: evil1.com appeared twice but should only be once
            assert len([d for d in domains if d == "evil1.com"]) == 1

    async def test_empty_feed(self):
        mock_client = _mock_httpx_client("")
        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_openphish()
            assert domains == []

    async def test_http_error(self):
        mock_client = _mock_httpx_client("", status_code=500)
        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_openphish()
            assert domains == []

    async def test_network_error(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("connection failed")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_openphish()
            assert domains == []


class TestFetchPhishingArmy:
    async def test_parse_blocklist(self):
        feed = "# Comment line\nevil1.com\nevil2.com\n# Another comment\nevil3.com\n"
        mock_client = _mock_httpx_client(feed)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_phishing_army()
            assert len(domains) == 3
            assert "evil1.com" in domains
            assert "evil2.com" in domains
            assert "evil3.com" in domains

    async def test_skip_comments_and_empty(self):
        feed = "# header\n\n\n# another\n   \n"
        mock_client = _mock_httpx_client(feed)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_phishing_army()
            assert domains == []


class TestFetchURLhaus:
    async def test_parse_csv(self):
        feed = (
            '# URLhaus dump\n'
            '# columns: id,"dateadded","url","url_status"\n'
            '"1","2026-01-01","https://evil1.com/malware","online"\n'
            '"2","2026-01-01","https://evil2.com/phish","online"\n'
        )
        mock_client = _mock_httpx_client(feed)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_urlhaus()
            assert "evil1.com" in domains
            assert "evil2.com" in domains


class TestFetchPhishTank:
    async def test_parse_csv(self):
        header = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
        rows = (
            '1,https://evil1.com/page,http://phishtank.com/1,2026-01-01,yes,2026-01-01,yes,Other\n'
            '2,https://evil2.com/login,http://phishtank.com/2,2026-01-01,yes,2026-01-01,yes,Other\n'
        )
        feed = header + rows

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = feed

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            domains = await fetch_phishtank()
            assert "evil1.com" in domains
            assert "evil2.com" in domains


class TestFetchCrtsh:
    async def test_parse_subdomains(self):
        json_resp = [
            {"name_value": "sub1.brou.com.uy\nsub2.brou.com.uy"},
            {"name_value": "*.brou.com.uy"},  # wildcard should be skipped
            {"name_value": "sub3.brou.com.uy"},
        ]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = json_resp

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            subs = await fetch_crtsh_subdomains("brou.com.uy")
            assert "sub1.brou.com.uy" in subs
            assert "sub2.brou.com.uy" in subs
            assert "sub3.brou.com.uy" in subs
            # Wildcards should be excluded
            assert not any(s.startswith("*") for s in subs)

    async def test_empty_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.ingestion.sources.httpx.AsyncClient", return_value=mock_client):
            subs = await fetch_crtsh_subdomains("unknown.com")
            assert subs == []


# ---------------------------------------------------------------------------
# fetch_all_blacklists
# ---------------------------------------------------------------------------

class TestFetchAllBlacklists:
    async def test_aggregates_sources(self):
        with patch("app.ingestion.sources.fetch_openphish", new_callable=AsyncMock) as m1, \
             patch("app.ingestion.sources.fetch_phishing_army", new_callable=AsyncMock) as m2, \
             patch("app.ingestion.sources.fetch_urlhaus", new_callable=AsyncMock) as m3, \
             patch("app.ingestion.sources.fetch_phishtank", new_callable=AsyncMock) as m4:
            m1.return_value = ["a.com", "b.com"]
            m2.return_value = ["c.com"]
            m3.return_value = ["d.com"]
            m4.return_value = ["e.com"]

            result = await fetch_all_blacklists()
            assert "openphish" in result
            assert "phishing_army" in result
            assert "urlhaus" in result
            assert "phishtank" in result
            assert result["openphish"] == ["a.com", "b.com"]

    async def test_handles_source_failure(self):
        with patch("app.ingestion.sources.fetch_openphish", new_callable=AsyncMock) as m1, \
             patch("app.ingestion.sources.fetch_phishing_army", new_callable=AsyncMock) as m2, \
             patch("app.ingestion.sources.fetch_urlhaus", new_callable=AsyncMock) as m3, \
             patch("app.ingestion.sources.fetch_phishtank", new_callable=AsyncMock) as m4:
            m1.side_effect = Exception("network error")
            m2.return_value = ["c.com"]
            m3.return_value = ["d.com"]
            m4.return_value = []

            result = await fetch_all_blacklists()
            assert result["openphish"] == []  # failed source returns empty
            assert result["phishing_army"] == ["c.com"]


# ---------------------------------------------------------------------------
# run_blacklist_ingestion (runner)
# ---------------------------------------------------------------------------

class TestRunBlacklistIngestion:
    async def test_adds_new_domains(self, mock_get_table, fake_table):
        with patch("app.ingestion.runner.fetch_all_blacklists", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                "openphish": ["new1.com", "new2.com"],
                "phishing_army": ["new3.com"],
            }

            stats = await run_blacklist_ingestion()
            assert stats["total_unique"] == 3
            assert stats["new_added"] == 3
            assert stats["already_known"] == 0

            # Verify all domains are in the store
            assert "new1.com" in fake_table._store
            assert "new2.com" in fake_table._store
            assert "new3.com" in fake_table._store

    async def test_upserts_existing_domains(self, mock_get_table, fake_table):
        """Ingestion upserts all domains without per-domain dedup (performance fix)."""
        fake_table._store["existing.com"] = {
            "domain": "existing.com", "entry_type": "blacklist",
        }

        with patch("app.ingestion.runner.fetch_all_blacklists", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                "openphish": ["existing.com", "new1.com"],
                "phishing_army": [],
            }

            stats = await run_blacklist_ingestion()
            assert stats["total_unique"] == 2
            # All domains upserted (no per-domain dedup for performance)
            assert stats["new_added"] == 2

    async def test_deduplication_across_sources(self, mock_get_table, fake_table):
        with patch("app.ingestion.runner.fetch_all_blacklists", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                "openphish": ["dup.com", "unique1.com"],
                "phishing_army": ["dup.com", "unique2.com"],
            }

            stats = await run_blacklist_ingestion()
            # "dup.com" appears in both sources but should be counted once
            assert stats["total_unique"] == 3
            assert stats["new_added"] == 3

    async def test_empty_feeds(self, mock_get_table):
        with patch("app.ingestion.runner.fetch_all_blacklists", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                "openphish": [],
                "phishing_army": [],
            }

            stats = await run_blacklist_ingestion()
            assert stats["total_unique"] == 0
            assert stats["new_added"] == 0


# ---------------------------------------------------------------------------
# run_whitelist_discovery
# ---------------------------------------------------------------------------

class TestRunWhitelistDiscovery:
    async def test_discovers_and_stores(self, mock_get_table, fake_table):
        with patch("app.ingestion.runner.fetch_crtsh_subdomains", new_callable=AsyncMock) as mock_crt:
            mock_crt.return_value = ["sub1.brou.com.uy", "sub2.brou.com.uy"]

            stats = await run_whitelist_discovery("brou.com.uy", "brou")
            assert stats["root_domain"] == "brou.com.uy"
            assert stats["discovered"] == 2
            assert stats["new_added"] == 2

            # Verify stored with correct partner_id
            assert "sub1.brou.com.uy" in fake_table._store
            assert fake_table._store["sub1.brou.com.uy"]["partner_id"] == "brou"

    async def test_skips_existing_subdomains(self, mock_get_table, fake_table):
        fake_table._store["sub1.brou.com.uy"] = {
            "domain": "sub1.brou.com.uy", "entry_type": "whitelist",
        }

        with patch("app.ingestion.runner.fetch_crtsh_subdomains", new_callable=AsyncMock) as mock_crt:
            mock_crt.return_value = ["sub1.brou.com.uy", "sub2.brou.com.uy"]

            stats = await run_whitelist_discovery("brou.com.uy", "brou")
            assert stats["discovered"] == 2
            assert stats["new_added"] == 1
            assert stats["already_known"] == 1

    async def test_no_subdomains_found(self, mock_get_table):
        with patch("app.ingestion.runner.fetch_crtsh_subdomains", new_callable=AsyncMock) as mock_crt:
            mock_crt.return_value = []

            stats = await run_whitelist_discovery("unknown.com", "partner")
            assert stats["discovered"] == 0
            assert stats["new_added"] == 0

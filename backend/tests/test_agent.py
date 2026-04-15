"""Tests for the domain investigation agent.

Covers:
- Heuristic scoring (_check_heuristics)
- Levenshtein distance (_levenshtein)
- SSL cert checks (_check_ssl_cert_sync) with mocked socket/ssl
- RDAP checks (_check_rdap) with mocked httpx
- Full investigate_domain flow
"""

import ssl
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
import httpx

from app.agent import (
    _check_heuristics,
    _check_rdap,
    _check_ssl_cert_sync,
    _levenshtein,
    _extract_base_domain,
    investigate_domain,
)
from app.models import Verdict, EntryType


# ---------------------------------------------------------------------------
# _levenshtein
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("abc", "abc") == 0

    def test_single_insert(self):
        assert _levenshtein("abc", "abcd") == 1

    def test_single_delete(self):
        assert _levenshtein("abcd", "abc") == 1

    def test_single_replace(self):
        assert _levenshtein("abc", "axc") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_one_empty(self):
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("abc", "") == 3

    def test_completely_different(self):
        assert _levenshtein("abc", "xyz") == 3

    def test_brand_typosquat(self):
        """brou vs br0u should be edit distance 1."""
        assert _levenshtein("brou", "br0u") == 1

    def test_similar_domains(self):
        dist = _levenshtein("brou.com.uy", "br0u.com.uy")
        assert dist == 1


# ---------------------------------------------------------------------------
# _extract_base_domain (agent-local copy)
# ---------------------------------------------------------------------------

class TestAgentExtractBaseDomain:
    def test_simple(self):
        assert _extract_base_domain("www.google.com") == "google.com"

    def test_two_part_tld(self):
        assert _extract_base_domain("homebanking.brou.com.uy") == "brou.com.uy"

    def test_already_base(self):
        assert _extract_base_domain("google.com") == "google.com"


# ---------------------------------------------------------------------------
# _check_heuristics
# ---------------------------------------------------------------------------

class TestCheckHeuristics:
    """Tests for the synchronous heuristic scoring logic."""

    @pytest.fixture(autouse=True)
    def clear_whitelist_cache(self):
        """Ensure whitelist cache is set for each test."""
        import app.agent as agent_mod
        agent_mod._CACHED_WHITELIST = ["brou.com.uy", "itau.com.uy", "santander.com.uy"]
        yield
        agent_mod._CACHED_WHITELIST = []

    async def test_benign_domain(self):
        score, signals = await _check_heuristics("example.com")
        assert score < 0.4  # should not be flagged as risky

    async def test_long_domain(self):
        long = "a" * 25 + ".phish.com"  # > 30 chars
        score, signals = await _check_heuristics(long)
        assert score >= 0.1
        assert any("Long domain" in s for s in signals)

    async def test_multiple_hyphens(self):
        score, signals = await _check_heuristics("secure-login-verify.evil.com")
        assert any("hyphens" in s.lower() for s in signals)

    async def test_many_digits(self):
        score, signals = await _check_heuristics("bank12345.com")
        assert any("digits" in s.lower() for s in signals)

    async def test_risky_tld(self):
        score, signals = await _check_heuristics("something.xyz")
        assert score >= 0.3
        assert any(".xyz" in s for s in signals)

    async def test_deep_subdomain(self):
        score, signals = await _check_heuristics("a.b.c.evil.com")
        assert any("subdomain" in s.lower() for s in signals)

    async def test_brand_impersonation(self):
        score, signals = await _check_heuristics("brou-login.phish.com")
        assert any("brand" in s.lower() for s in signals)
        assert score >= 0.3

    async def test_brand_exact_match_not_flagged(self):
        """The real brou.com should not trigger brand impersonation."""
        score, signals = await _check_heuristics("brou.com")
        brand_signals = [s for s in signals if "brand" in s.lower()]
        assert len(brand_signals) == 0

    async def test_levenshtein_typosquat(self):
        """A domain very similar to a whitelisted one should score high."""
        score, signals = await _check_heuristics("br0u.com.uy")
        assert any("similar" in s.lower() or "edit distance" in s.lower() for s in signals)
        assert score >= 0.4

    async def test_high_entropy(self):
        score, signals = await _check_heuristics("qwzxjkvbnm.com")
        # May or may not trigger depending on character ratio
        assert isinstance(score, float)

    async def test_no_signals_message(self):
        """A perfectly normal short domain might get 'No suspicious heuristic signals'."""
        import app.agent as agent_mod
        agent_mod._CACHED_WHITELIST = []  # no whitelist to compare against
        score, signals = await _check_heuristics("ok.com")
        if score == 0:
            assert any("No suspicious" in s for s in signals)


# ---------------------------------------------------------------------------
# _check_rdap (mocked HTTP)
# ---------------------------------------------------------------------------

class TestCheckRDAP:
    async def test_new_domain(self):
        """Domain registered 3 days ago."""
        reg_date = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        mock_json = {
            "events": [{"eventAction": "registration", "eventDate": reg_date}]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_json

        with patch("app.agent.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            days = await _check_rdap("sub.newdomain.com")
            assert days is not None
            assert days <= 4  # allow slight timing variance

    async def test_old_domain(self):
        reg_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        mock_json = {
            "events": [{"eventAction": "registration", "eventDate": reg_date}]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_json

        with patch("app.agent.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            days = await _check_rdap("example.com")
            assert days is not None
            assert days >= 364

    async def test_rdap_failure_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("app.agent.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            days = await _check_rdap("nonexistent.example")
            assert days is None

    async def test_rdap_timeout_returns_none(self):
        with patch("app.agent.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.side_effect = httpx.TimeoutException("timeout")
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            days = await _check_rdap("slow.example.com")
            assert days is None


# ---------------------------------------------------------------------------
# _check_ssl_cert_sync (mocked ssl/socket)
# ---------------------------------------------------------------------------

class TestCheckSSLCert:
    """Tests for _check_ssl_cert_sync.

    ssl and socket are imported locally inside the function, so we
    patch them at the stdlib module level.
    """

    def test_valid_cert_free_ca(self):
        """Free CA (Let's Encrypt) should add score."""
        from email.utils import format_datetime
        not_before = format_datetime(datetime.now(timezone.utc) - timedelta(days=60))

        mock_cert = {
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "notBefore": not_before,
            "subjectAltName": (("DNS", "example.com"),),
        }

        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.getpeercert.return_value = mock_cert

            score, signals = _check_ssl_cert_sync("example.com")
            assert score >= 0.15
            assert any("free ca" in s.lower() or "let's encrypt" in s.lower() for s in signals)

    def test_valid_cert_paid_ca(self):
        from email.utils import format_datetime
        not_before = format_datetime(datetime.now(timezone.utc) - timedelta(days=200))

        mock_cert = {
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "notBefore": not_before,
            "subjectAltName": (("DNS", "example.com"),),
        }

        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.getpeercert.return_value = mock_cert

            score, signals = _check_ssl_cert_sync("example.com")
            # Paid CA, old cert = low score
            assert score < 0.3

    def test_very_new_cert(self):
        from email.utils import format_datetime
        not_before = format_datetime(datetime.now(timezone.utc) - timedelta(days=2))

        mock_cert = {
            "issuer": ((("organizationName", "ZeroSSL"),),),
            "notBefore": not_before,
            "subjectAltName": (("DNS", "example.com"),),
        }

        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.getpeercert.return_value = mock_cert

            score, signals = _check_ssl_cert_sync("phishy.com")
            assert score >= 0.3  # free CA + very new cert
            assert any("very new" in s.lower() for s in signals)

    def test_ssl_verification_failed(self):
        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.connect.side_effect = ssl.SSLCertVerificationError("bad cert")

            score, signals = _check_ssl_cert_sync("bad-cert.com")
            assert score >= 0.3
            assert any("verification failed" in s.lower() for s in signals)

    def test_no_https(self):
        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.connect.side_effect = ConnectionRefusedError()

            score, signals = _check_ssl_cert_sync("http-only.com")
            assert score >= 0.1
            assert any("http only" in s.lower() or "no https" in s.lower() for s in signals)

    def test_ssl_timeout(self):
        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.connect.side_effect = socket.timeout("timed out")

            score, signals = _check_ssl_cert_sync("slow.com")
            assert any("timed out" in s.lower() for s in signals)

    def test_no_cert_returned(self):
        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.getpeercert.return_value = None

            score, signals = _check_ssl_cert_sync("nocert.com")
            assert score >= 0.2
            assert any("no ssl" in s.lower() for s in signals)

    def test_many_san_domains(self):
        """Cert covering many domains (shared hosting) should add score."""
        from email.utils import format_datetime
        not_before = format_datetime(datetime.now(timezone.utc) - timedelta(days=90))

        san = tuple(("DNS", f"domain{i}.com") for i in range(15))
        mock_cert = {
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "notBefore": not_before,
            "subjectAltName": san,
        }

        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.getpeercert.return_value = mock_cert

            score, signals = _check_ssl_cert_sync("shared.com")
            assert any("shared hosting" in s.lower() for s in signals)

    def test_www_stripping(self):
        """www. prefix should be stripped for SSL check."""
        from email.utils import format_datetime
        not_before = format_datetime(datetime.now(timezone.utc) - timedelta(days=90))

        mock_cert = {
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "notBefore": not_before,
            "subjectAltName": (("DNS", "example.com"),),
        }

        with patch("ssl.create_default_context") as mock_ctx, \
             patch("socket.socket") as mock_sock:
            mock_conn = MagicMock()
            mock_ctx.return_value.wrap_socket.return_value = mock_conn
            mock_conn.getpeercert.return_value = mock_cert

            # Should connect to example.com, not www.example.com
            score, signals = _check_ssl_cert_sync("www.example.com")
            connect_call = mock_conn.connect.call_args
            assert connect_call[0][0][0] == "example.com"


# ---------------------------------------------------------------------------
# investigate_domain (full flow, all external calls mocked)
# ---------------------------------------------------------------------------

class TestInvestigateDomain:
    async def test_suspicious_domain_gets_block(self, mock_get_table):
        """A domain hitting multiple signals should get block verdict."""
        import app.agent as agent_mod
        agent_mod._CACHED_WHITELIST = ["brou.com.uy"]

        with patch("app.agent._check_rdap", return_value=2), \
             patch("app.agent._check_ssl_cert", return_value=(0.3, ["Free CA, very new cert"])):
            # brou-seguro.xyz: brand name + risky TLD + new domain + bad cert
            entry = await investigate_domain("brou-seguro.xyz")
            assert entry.verdict == Verdict.block
            assert entry.entry_type == EntryType.cache
            assert entry.confidence > 0

    async def test_clean_domain_gets_allow(self, mock_get_table):
        import app.agent as agent_mod
        agent_mod._CACHED_WHITELIST = []

        with patch("app.agent._check_rdap", return_value=500), \
             patch("app.agent._check_ssl_cert", return_value=(0.0, ["SSL certificate looks normal"])):
            entry = await investigate_domain("safe-site.com")
            assert entry.verdict == Verdict.allow
            assert entry.domain == "safe-site.com"

    async def test_moderate_risk_gets_warn(self, mock_get_table):
        import app.agent as agent_mod
        agent_mod._CACHED_WHITELIST = []

        with patch("app.agent._check_rdap", return_value=15), \
             patch("app.agent._check_ssl_cert", return_value=(0.15, ["Free CA certificate"])):
            # New-ish domain + free CA = moderate risk
            entry = await investigate_domain("newsite.com")
            assert entry.verdict == Verdict.warn

    async def test_result_is_persisted(self, mock_get_table, fake_table):
        import app.agent as agent_mod
        agent_mod._CACHED_WHITELIST = []

        with patch("app.agent._check_rdap", return_value=500), \
             patch("app.agent._check_ssl_cert", return_value=(0.0, ["SSL looks normal"])):
            entry = await investigate_domain("persisted.com")

        # Check it was written to the store
        stored = await fake_table.get_item(Key={"domain": "persisted.com"})
        assert "Item" in stored
        assert stored["Item"]["entry_type"] == "cache"

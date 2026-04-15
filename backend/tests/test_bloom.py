"""Tests for bloom filter generation, checking, and base domain extraction."""

import pytest

from app.bloom import (
    build_bloom_filter,
    check_bloom_filter,
    extract_base_domain,
    _optimal_params,
)


# ---------------------------------------------------------------------------
# extract_base_domain
# ---------------------------------------------------------------------------

class TestExtractBaseDomain:
    def test_simple_two_part(self):
        assert extract_base_domain("google.com") == "google.com"

    def test_strip_www(self):
        assert extract_base_domain("www.google.com") == "google.com"

    def test_deep_subdomain(self):
        assert extract_base_domain("a.b.c.google.com") == "google.com"

    def test_two_part_tld_uy(self):
        assert extract_base_domain("brou.com.uy") == "brou.com.uy"

    def test_two_part_tld_with_subdomain(self):
        assert extract_base_domain("homebanking.brou.com.uy") == "brou.com.uy"

    def test_two_part_tld_uk(self):
        assert extract_base_domain("www.example.co.uk") == "example.co.uk"

    def test_two_part_tld_ar(self):
        assert extract_base_domain("mail.banco.com.ar") == "banco.com.ar"

    def test_single_part_unchanged(self):
        # Edge case: bare TLD or single-label domain
        assert extract_base_domain("localhost") == "localhost"

    def test_case_insensitive(self):
        assert extract_base_domain("WWW.Google.COM") == "google.com"

    def test_trailing_dot(self):
        assert extract_base_domain("google.com.") == "google.com"

    def test_gob_uy(self):
        assert extract_base_domain("tramites.gub.gob.uy") == "gub.gob.uy"

    def test_xyz_tld(self):
        """Non-two-part TLD should return last two parts."""
        assert extract_base_domain("sub.evil.xyz") == "evil.xyz"


# ---------------------------------------------------------------------------
# _optimal_params
# ---------------------------------------------------------------------------

class TestOptimalParams:
    def test_returns_positive_values(self):
        m, k = _optimal_params(1000, 0.001)
        assert m > 0
        assert k > 0

    def test_small_n_uses_minimum(self):
        m, k = _optimal_params(1, 0.001)
        assert m >= 64
        assert k >= 1

    def test_zero_n_no_crash(self):
        m, k = _optimal_params(0, 0.01)
        assert m >= 64
        assert k >= 1

    def test_larger_n_produces_larger_filter(self):
        m1, _ = _optimal_params(100, 0.01)
        m2, _ = _optimal_params(10000, 0.01)
        assert m2 > m1

    def test_lower_fp_rate_larger_filter(self):
        m1, _ = _optimal_params(1000, 0.1)
        m2, _ = _optimal_params(1000, 0.001)
        assert m2 > m1


# ---------------------------------------------------------------------------
# build_bloom_filter / check_bloom_filter
# ---------------------------------------------------------------------------

class TestBloomFilter:
    def test_known_domain_found(self):
        domains = ["evil.com", "phish.xyz", "badsite.org"]
        data = build_bloom_filter(domains, fp_rate=0.001)
        for d in domains:
            assert check_bloom_filter(data, d) is True

    def test_unknown_domain_likely_absent(self):
        domains = ["evil.com", "phish.xyz"]
        data = build_bloom_filter(domains, fp_rate=0.0001)
        # With very low fp rate and few domains, false positives are rare
        absent = ["google.com", "apple.com", "microsoft.com", "amazon.com", "github.com"]
        false_positives = sum(1 for d in absent if check_bloom_filter(data, d))
        # Allow at most 1 false positive out of 5 checks
        assert false_positives <= 1

    def test_case_insensitive(self):
        domains = ["Evil.Com"]
        data = build_bloom_filter(domains, fp_rate=0.001)
        assert check_bloom_filter(data, "evil.com") is True
        assert check_bloom_filter(data, "EVIL.COM") is True

    def test_empty_domain_list(self):
        """Empty list still produces a valid bloom filter (uses min n=10)."""
        data = build_bloom_filter([], fp_rate=0.01)
        assert len(data) > 8  # at least header
        # Nothing should match (except possible false positives)
        assert isinstance(check_bloom_filter(data, "test.com"), bool)

    def test_serialization_format(self):
        """First 8 bytes are m and k as big-endian 4-byte ints."""
        data = build_bloom_filter(["example.com"], fp_rate=0.01)
        m = int.from_bytes(data[:4], "big")
        k = int.from_bytes(data[4:8], "big")
        assert m > 0
        assert k > 0
        # Remaining bytes should be the bitarray
        assert len(data) > 8

    def test_large_domain_set(self):
        """Build filter with many domains and verify all are found."""
        domains = [f"domain-{i}.com" for i in range(500)]
        data = build_bloom_filter(domains, fp_rate=0.001)
        for d in domains:
            assert check_bloom_filter(data, d) is True


# ---------------------------------------------------------------------------
# Async bloom generation (mocked DB)
# ---------------------------------------------------------------------------

class TestAsyncBloomGeneration:
    async def test_generate_whitelist_bloom(self, mock_get_table, fake_table):
        """generate_whitelist_bloom uses scan_by_type and builds a filter."""
        # Seed whitelist entries
        await fake_table.put_item(Item={
            "domain": "brou.com.uy", "entry_type": "whitelist", "partner_id": "brou",
        })
        await fake_table.put_item(Item={
            "domain": "itau.com.uy", "entry_type": "whitelist", "partner_id": "itau",
        })
        await fake_table.put_item(Item={
            "domain": "evil.com", "entry_type": "blacklist",
        })

        from app.bloom import generate_whitelist_bloom
        data = await generate_whitelist_bloom()
        assert len(data) > 8
        assert check_bloom_filter(data, "brou.com.uy") is True
        assert check_bloom_filter(data, "itau.com.uy") is True

    async def test_generate_blacklist_bloom(self, mock_get_table, fake_table):
        await fake_table.put_item(Item={
            "domain": "evil.com", "entry_type": "blacklist",
        })
        await fake_table.put_item(Item={
            "domain": "brou.com.uy", "entry_type": "whitelist", "partner_id": "brou",
        })

        from app.bloom import generate_blacklist_bloom
        data = await generate_blacklist_bloom()
        assert check_bloom_filter(data, "evil.com") is True

    async def test_generate_bloom_filters_stats(self, mock_get_table, fake_table):
        await fake_table.put_item(Item={"domain": "safe.com", "entry_type": "whitelist"})
        await fake_table.put_item(Item={"domain": "bad.com", "entry_type": "blacklist"})

        from app.bloom import generate_bloom_filters
        result = await generate_bloom_filters()

        assert "whitelist" in result
        assert "blacklist" in result
        assert result["whitelist"]["total_entries"] == 1
        assert result["blacklist"]["total_entries"] == 1
        assert result["whitelist"]["bloom_size_bytes"] > 0

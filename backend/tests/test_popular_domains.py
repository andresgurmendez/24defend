"""Tests for app.popular_domains — the pre-agent short-circuit source."""

import pytest

from app.popular_domains import (
    PopularDomains,
    VENDOR_ALLOWLIST,
    get_instance,
    reset_for_tests,
)


@pytest.fixture(autouse=True)
def clean_singleton():
    """Reset the module-level singleton around each test."""
    reset_for_tests()
    yield
    reset_for_tests()


class TestVendorAllowlist:
    def test_vendor_allowlist_available_without_load(self):
        """is_popular() should work off the vendor list before Majestic loads."""
        pd = PopularDomains()
        assert pd.is_popular("cloudflare.net")
        assert pd.is_popular("api.cloudflare.net")   # eTLD+1 lookup
        assert pd.is_popular("zetaglobal.net")

    def test_non_vendor_domain_is_not_popular_without_load(self):
        pd = PopularDomains()
        assert not pd.is_popular("evil-bank.com")
        assert not pd.is_popular("brou-actualiza-cuenta-2026.com")


class TestIsPopular:
    def test_uses_base_domain_not_exact_match(self):
        """A subdomain should match if its eTLD+1 is in the popular set."""
        pd = PopularDomains()
        # aa.com is in VENDOR_ALLOWLIST
        assert pd.is_popular("l.loyalty.ms.aa.com")
        assert pd.is_popular("aa.com")

    def test_empty_domain(self):
        pd = PopularDomains()
        assert not pd.is_popular("")

    def test_uruguayan_two_part_tld(self):
        """extract_base_domain handles .com.uy correctly; verify no accidental match."""
        pd = PopularDomains()
        # oca.com.uy should not be treated as "uy" or "com.uy"
        assert not pd.is_popular("oca.com.uy")  # not in vendor list


class TestKnownFPsFromProdCache:
    """Regression: these domains were confirmed FPs in the DDB cache. Their
    eTLD+1 is in the vendor allowlist so is_popular() must short-circuit
    them before the agent runs."""

    @pytest.mark.parametrize("domain", [
        "certificates.godaddy.com",
        "l.loyalty.ms.aa.com",
        "email.columbia.com.et.bm16.maas.zetaglobal.net",
        "email.columbia.com.images.maas.zetaglobal.net",
        "tlbrb54lgvvny8ykr6sqhbs16ct1.click-sap.sfmc-marketing.com",
        "6worbaa.ng.impervadns.net",
        "thirdparty.bnc.lt",
        "hosts.vggwebsitetrackingprod.azurewebsites.net",
        "links.h5.hilton.com",
        "links1.washingtonpost.com",
        "57170hye.r.us-east-2.awstrack.me",
        "email.mg-d0.substack.com",
        "www.movable-ink-1505.com",
    ])
    def test_prod_fp_is_short_circuited(self, domain: str):
        pd = PopularDomains()
        assert pd.is_popular(domain), (
            f"FP domain {domain} should be caught by the pre-agent short-circuit"
        )


class TestKnownPhishingNotAllowed:
    """Regression: known phishing domains must NOT be short-circuited."""

    @pytest.mark.parametrize("domain", [
        "premios.oca.hk",
        "www.promotion.oca.st",
        "sucive.oca.st",
        "www.puntos.santader.st",
        "brou-actualiza-tu-cuenta-2026-uy.com",
        "paypa1-seguro-login.com",
        "bancosantander-clave.net",
    ])
    def test_phishing_not_allowed(self, domain: str):
        pd = PopularDomains()
        assert not pd.is_popular(domain)


class TestSingleton:
    def test_get_instance_returns_same_object(self):
        a = get_instance()
        b = get_instance()
        assert a is b

    def test_reset_for_tests_creates_new_instance(self):
        a = get_instance()
        reset_for_tests()
        b = get_instance()
        assert a is not b


class TestLoadMajestic:
    @pytest.mark.asyncio
    async def test_load_majestic_from_local_csv(self, tmp_path, monkeypatch):
        """Loading a small local CSV should extend the popular set."""
        csv = tmp_path / "majestic.csv"
        csv.write_text(
            "GlobalRank,TldRank,Domain\n"
            "1,1,google.com\n"
            "2,2,example.com\n"
            "3,3,domain-under-test.io\n"
        )

        # Monkey-patch httpx.AsyncClient.get to return the file's contents
        import httpx

        class FakeResp:
            status_code = 200
            text = csv.read_text()

        class FakeClient:
            def __init__(self, *_, **__): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
            async def get(self, url):
                return FakeResp()

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

        pd = PopularDomains()
        total = await pd.load_majestic(url="ignored")
        assert pd.is_popular("domain-under-test.io")
        assert pd.is_popular("example.com")
        # Vendor list still present after merge
        assert pd.is_popular("cloudflare.net")
        assert total == pd.size()

    @pytest.mark.asyncio
    async def test_load_majestic_falls_back_on_error(self, monkeypatch):
        """A network error must not break is_popular — falls back to vendor list."""
        import httpx

        class FailingClient:
            def __init__(self, *_, **__): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
            async def get(self, url):
                raise httpx.RequestError("boom")

        monkeypatch.setattr(httpx, "AsyncClient", FailingClient)

        pd = PopularDomains()
        original_size = pd.size()
        total = await pd.load_majestic(url="ignored")
        assert total == original_size  # vendor list only
        assert pd.is_popular("cloudflare.net")

    @pytest.mark.asyncio
    async def test_load_majestic_falls_back_on_non_200(self, monkeypatch):
        """A 500 response also falls back cleanly."""
        import httpx

        class BadResp:
            status_code = 500
            text = ""

        class BadClient:
            def __init__(self, *_, **__): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
            async def get(self, url):
                return BadResp()

        monkeypatch.setattr(httpx, "AsyncClient", BadClient)

        pd = PopularDomains()
        await pd.load_majestic(url="ignored")
        assert pd.is_popular("cloudflare.net")


class TestVendorAllowlistIsLowercase:
    """Guard against a typo that would silently break is_popular()."""

    def test_all_vendors_are_lowercase(self):
        for v in VENDOR_ALLOWLIST:
            assert v == v.lower()

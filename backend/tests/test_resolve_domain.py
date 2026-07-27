"""Tests for the resolve_domain agent tool and its helpers.

Covers the four sub-checks (CNAME chain, IP owner, reverse DNS, TLS cert)
independently, plus the guardrails: loop protection, generic-PTR flagging,
cloud-IP neutrality labeling, and per-check isolation (one failing check
must not break the whole tool).
"""

from unittest.mock import MagicMock, patch

from app.investigation.tools import (
    _CDN_ALIAS_SUFFIXES,
    _CLOUD_IP_OWNERS,
    _GENERIC_PTR_SUFFIXES,
    _detect_cdn_alias,
    _follow_cname_chain,
    _lookup_ip_owner,
    _reverse_dns,
    _tls_cert_subject,
    resolve_domain,
)


# ---------------------------------------------------------------------------
# CNAME chain — loop protection, hop cap, mixed CNAME/A responses
# ---------------------------------------------------------------------------

def _mock_doh(rrsets: dict[str, list[dict]]):
    """Build a patch for `_resolve_dns_via_doh` that returns per-hostname rrsets."""
    def side_effect(hostname: str, rrtype: str = "A"):
        return {"Answer": rrsets.get(hostname.lower(), [])}
    return patch("app.investigation.tools._resolve_dns_via_doh", side_effect=side_effect)


class TestFollowCnameChain:

    def test_direct_a_record_no_chain(self):
        with _mock_doh({"foo.com": [{"type": 1, "data": "1.2.3.4"}]}):
            chain, ips = _follow_cname_chain("foo.com")
        assert chain == []
        assert ips == ["1.2.3.4"]

    def test_single_cname_hop(self):
        with _mock_doh({
            "foo.com": [{"type": 5, "data": "cdn.example.net."}],
            "cdn.example.net": [{"type": 1, "data": "9.9.9.9"}],
        }):
            chain, ips = _follow_cname_chain("foo.com")
        assert chain == ["cdn.example.net"]
        assert ips == ["9.9.9.9"]

    def test_multi_hop_walmart_pattern(self):
        with _mock_doh({
            "www.walmart.com.cdn-wal.net": [
                {"type": 5, "data": "www.walmart.com.edgekey.net."},
            ],
            "www.walmart.com.edgekey.net": [
                {"type": 5, "data": "e4373.x.akamaiedge.net."},
            ],
            "e4373.x.akamaiedge.net": [
                {"type": 1, "data": "23.208.208.163"},
            ],
        }):
            chain, ips = _follow_cname_chain("www.walmart.com.cdn-wal.net")
        assert chain == [
            "www.walmart.com.edgekey.net",
            "e4373.x.akamaiedge.net",
        ]
        assert ips == ["23.208.208.163"]

    def test_loop_protection(self):
        """A → B → A must terminate, not infinite-loop."""
        with _mock_doh({
            "a.com": [{"type": 5, "data": "b.com."}],
            "b.com": [{"type": 5, "data": "a.com."}],
        }):
            chain, ips = _follow_cname_chain("a.com", max_hops=10)
        # First hop goes A→B; the next iteration would revisit A, so it stops.
        assert chain == ["b.com"]
        assert ips == []

    def test_max_hops_cap(self):
        # Chain longer than max_hops — must be truncated.
        graph = {f"h{i}.com": [{"type": 5, "data": f"h{i+1}.com."}] for i in range(10)}
        graph["h10.com"] = [{"type": 1, "data": "8.8.8.8"}]
        with _mock_doh(graph):
            chain, ips = _follow_cname_chain("h0.com", max_hops=3)
        assert len(chain) == 3
        # We stopped before reaching the terminal A record.
        assert ips == []

    def test_empty_answer_returns_empty(self):
        with _mock_doh({"nothing.example": []}):
            chain, ips = _follow_cname_chain("nothing.example")
        assert chain == []
        assert ips == []


# ---------------------------------------------------------------------------
# CDN alias detection
# ---------------------------------------------------------------------------

class TestDetectCdnAlias:

    def test_akamai_edgekey(self):
        provider, customer = _detect_cdn_alias(["www.walmart.com.edgekey.net"])
        assert provider == "Akamai"
        assert customer == "www.walmart.com"

    def test_azure_front_door(self):
        provider, customer = _detect_cdn_alias(["shop-prod.azureedge.net"])
        assert provider == "Azure Front Door"
        assert customer == "shop-prod"

    def test_no_match(self):
        provider, customer = _detect_cdn_alias(["random.example.net"])
        assert provider is None
        assert customer is None

    def test_picks_first_matching_hop(self):
        # Even if the terminal hop is akamaiedge.net (internal), we prefer
        # the customer-alias hop where the label carries the brand name.
        provider, customer = _detect_cdn_alias([
            "www.walmart.com.edgekey.net",
            "e4373.x.akamaiedge.net",
        ])
        assert provider == "Akamai"
        assert customer == "www.walmart.com"

    def test_all_configured_cdns_covered(self):
        """Every entry in _CDN_ALIAS_SUFFIXES must actually match."""
        for suffix, provider in _CDN_ALIAS_SUFFIXES.items():
            got_provider, got_customer = _detect_cdn_alias([f"brand-x.{suffix}"])
            assert got_provider == provider, f"failed for {suffix}"
            assert got_customer == "brand-x"


# ---------------------------------------------------------------------------
# IP owner lookup — cloud vs specific-corporate labeling
# ---------------------------------------------------------------------------

def _mock_rdap_ip(payload: dict, status: int = 200):
    def _ctx(*args, **kwargs):
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = payload
        client.get.return_value = resp
        cm = MagicMock()
        cm.__enter__.return_value = client
        cm.__exit__.return_value = False
        return cm
    return patch("app.investigation.tools.httpx.Client", side_effect=_ctx)


class TestLookupIpOwner:

    def test_specific_corporate_owner(self):
        payload = {
            "name": "ANTEL",
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["org", {}, "text", "CLIENTE ANTEL URUGUAY"]]],
                },
            ],
        }
        with _mock_rdap_ip(payload):
            owner, neutral = _lookup_ip_owner("179.27.154.250")
        assert owner == "CLIENTE ANTEL URUGUAY"
        assert neutral is None  # specific brand — not flagged as cloud

    def test_cloud_owner_marked_neutral(self):
        for owner_str in [
            "Akamai Technologies, Inc.",
            "Amazon Data Services",
            "Cloudflare, Inc.",
            "Google LLC",
            "Microsoft Corporation",
        ]:
            payload = {
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["org", {}, "text", owner_str]]],
                    },
                ],
            }
            with _mock_rdap_ip(payload):
                owner, neutral = _lookup_ip_owner("1.2.3.4")
            assert owner == owner_str
            assert neutral is not None, f"cloud owner not flagged: {owner_str}"
            assert "NEUTRAL" in neutral

    def test_falls_back_to_top_level_name(self):
        payload = {"name": "AKAMAI"}
        with _mock_rdap_ip(payload):
            owner, neutral = _lookup_ip_owner("1.2.3.4")
        assert owner == "AKAMAI"
        assert neutral is not None
        assert "NEUTRAL" in neutral

    def test_returns_none_on_lookup_failure(self):
        """RDAP down / non-200 / json error must not raise."""
        with _mock_rdap_ip({}, status=500):
            owner, neutral = _lookup_ip_owner("1.2.3.4")
        assert owner is None
        assert neutral is None

    def test_returns_none_on_exception(self):
        with patch("app.investigation.tools.httpx.Client", side_effect=Exception("boom")):
            owner, neutral = _lookup_ip_owner("1.2.3.4")
        assert owner is None
        assert neutral is None

    def test_all_configured_cloud_owners_flagged(self):
        """Every entry in _CLOUD_IP_OWNERS must produce a NEUTRAL flag."""
        for keyword in _CLOUD_IP_OWNERS:
            payload = {"name": f"Some {keyword} Corp"}
            with _mock_rdap_ip(payload):
                _, neutral = _lookup_ip_owner("1.2.3.4")
            assert neutral is not None, f"cloud keyword not flagged: {keyword}"


# ---------------------------------------------------------------------------
# Reverse DNS — generic hosting PTR flagging
# ---------------------------------------------------------------------------

class TestReverseDns:

    def test_generic_ptr_flagged(self):
        for ptr in [
            "ec2-1-2-3-4.compute.amazonaws.com",
            "a23-208-208-163.deploy.static.akamaitechnologies.com",
            "any-in-x9c.1e100.net",
            "d1234.cloudfront.net",
        ]:
            with patch("app.investigation.tools.socket.gethostbyaddr",
                       return_value=(ptr, [], ["1.2.3.4"])):
                got, is_generic = _reverse_dns("1.2.3.4")
            assert got == ptr
            assert is_generic, f"PTR not flagged generic: {ptr}"

    def test_specific_ptr_not_flagged(self):
        with patch("app.investigation.tools.socket.gethostbyaddr",
                   return_value=("mail.antel.com.uy", [], ["1.2.3.4"])):
            got, is_generic = _reverse_dns("1.2.3.4")
        assert got == "mail.antel.com.uy"
        assert not is_generic

    def test_ptr_failure_returns_none(self):
        with patch("app.investigation.tools.socket.gethostbyaddr",
                   side_effect=OSError("no ptr")):
            got, is_generic = _reverse_dns("1.2.3.4")
        assert got is None
        assert is_generic is False

    def test_all_generic_suffixes_matched(self):
        for suffix in _GENERIC_PTR_SUFFIXES:
            ptr = f"host123{suffix}"
            with patch("app.investigation.tools.socket.gethostbyaddr",
                       return_value=(ptr, [], ["1.2.3.4"])):
                _, is_generic = _reverse_dns("1.2.3.4")
            assert is_generic, f"generic suffix not detected: {suffix}"


# ---------------------------------------------------------------------------
# TLS cert subject — issuer/SAN/free-CA flagging
# ---------------------------------------------------------------------------

class TestTlsCertSubject:

    def _mock_conn(self, cert: dict):
        conn = MagicMock()
        conn.getpeercert.return_value = cert
        return conn

    def test_extracts_cn_san_issuer(self):
        cert = {
            "subject": ((("commonName", "www.walmart.com"),),),
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "subjectAltName": (("DNS", "www.walmart.com"), ("DNS", "walmart.com")),
        }
        ctx = MagicMock()
        ctx.wrap_socket.return_value = self._mock_conn(cert)
        with patch("app.investigation.tools.ssl.create_default_context", return_value=ctx), \
             patch("app.investigation.tools.socket.socket"):
            got = _tls_cert_subject("www.walmart.com.cdn-wal.net")
        assert got["subject_cn"] == "www.walmart.com"
        assert "walmart.com" in got["san_dns"]
        assert got["issuer_org"] == "DigiCert Inc"
        assert got["is_free_ca"] is False

    def test_flags_free_ca(self):
        cert = {
            "subject": ((("commonName", "phish.example"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "phish.example"),),
        }
        ctx = MagicMock()
        ctx.wrap_socket.return_value = self._mock_conn(cert)
        with patch("app.investigation.tools.ssl.create_default_context", return_value=ctx), \
             patch("app.investigation.tools.socket.socket"):
            got = _tls_cert_subject("phish.example")
        assert got["is_free_ca"] is True

    def test_failure_returns_empty_dict(self):
        """A failing TLS handshake must return {} — not raise."""
        with patch("app.investigation.tools.ssl.create_default_context",
                   side_effect=OSError("no ssl")):
            got = _tls_cert_subject("nothings.example")
        assert got == {}


# ---------------------------------------------------------------------------
# Full tool integration — isolated failures
# ---------------------------------------------------------------------------

class TestResolveDomainIntegration:

    def test_full_walmart_shape(self):
        """End-to-end mock of the Walmart CDN pattern the tool was
        specifically designed to catch."""
        with _mock_doh({
            "www.walmart.com.cdn-wal.net": [
                {"type": 5, "data": "www.walmart.com.edgekey.net."},
            ],
            "www.walmart.com.edgekey.net": [
                {"type": 5, "data": "e4373.x.akamaiedge.net."},
            ],
            "e4373.x.akamaiedge.net": [
                {"type": 1, "data": "23.208.208.163"},
            ],
        }), \
             _mock_rdap_ip({"name": "Akamai Technologies, Inc."}), \
             patch("app.investigation.tools.socket.gethostbyaddr",
                   return_value=("a23-208-208-163.deploy.static.akamaitechnologies.com", [], ["23.208.208.163"])), \
             patch("app.investigation.tools.ssl.create_default_context", side_effect=OSError()):
            out = resolve_domain.invoke({"domain": "www.walmart.com.cdn-wal.net"})

        # CNAME chain fully surfaced
        assert "www.walmart.com.edgekey.net" in out
        assert "e4373.x.akamaiedge.net" in out
        # CDN alias flagged with customer identity — the smoking gun
        assert "Akamai customer 'www.walmart.com'" in out
        # IP owner shown + labeled NEUTRAL (Akamai is shared infra)
        assert "Akamai Technologies" in out
        assert "NEUTRAL" in out
        # PTR shown + labeled GENERIC
        assert "deploy.static.akamaitechnologies.com" in out
        assert "GENERIC" in out
        # TLS failure did NOT break the tool
        assert "TLS certificate: could not fetch" in out

    def test_dns_failure_does_not_crash(self):
        """Tool must still return SOMETHING even if every sub-check fails."""
        with _mock_doh({}), \
             _mock_rdap_ip({}, status=500), \
             patch("app.investigation.tools.socket.gethostbyaddr", side_effect=OSError()), \
             patch("app.investigation.tools.ssl.create_default_context", side_effect=OSError()):
            out = resolve_domain.invoke({"domain": "no.such.thing"})
        assert "DNS resolution failed" in out
        assert "TLS certificate: could not fetch" in out

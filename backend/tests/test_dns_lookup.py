"""Tests for the enhanced RDAP tool.

Verifies that dns_lookup extracts:
1. Registrant / admin / tech organization names (was missing — the
   root cause of the dhmedia.io / ttdns2.com / adsensecustomsearchads.com
   family of false positives, where the agent didn't see WHO owned the
   domain).
2. ALL nameservers (not just the first 3), since the nameserver suffix
   is often the strongest legitimate-operator signal.
"""

from unittest.mock import MagicMock, patch

from app.investigation.tools import dns_lookup, _extract_org_from_vcard


# ---------------------------------------------------------------------------
# vCard helpers
# ---------------------------------------------------------------------------

class TestExtractOrgFromVcard:
    def test_pulls_org_field(self):
        vcard = [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Some Contact"],
            ["org", {}, "text", "Google LLC"],
        ]
        assert _extract_org_from_vcard(vcard) == "Google LLC"

    def test_org_can_be_list(self):
        # Some RDAP registries return org as [org, dept, ...]
        vcard = [
            ["org", {}, "text", ["TikTok Ltd", "Legal"]],
        ]
        assert _extract_org_from_vcard(vcard) == "TikTok Ltd"

    def test_falls_back_to_fn_when_no_org(self):
        vcard = [
            ["fn", {}, "text", "Delivery Hero SE"],
        ]
        assert _extract_org_from_vcard(vcard) == "Delivery Hero SE"

    def test_returns_none_on_empty_vcard(self):
        assert _extract_org_from_vcard([]) is None

    def test_skips_malformed_entries(self):
        vcard = [
            "not-a-list",
            ["short"],
            ["org", {}, "text", "Real Corp"],
        ]
        assert _extract_org_from_vcard(vcard) == "Real Corp"


# ---------------------------------------------------------------------------
# dns_lookup output (integration with parsing)
# ---------------------------------------------------------------------------

def _mock_rdap_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = payload
    return resp


class TestDnsLookupOutput:

    def _run(self, payload: dict, domain: str = "example.com") -> str:
        """Invoke the tool with the RDAP response mocked."""
        with patch("app.investigation.tools.httpx.Client") as mock_client_cls:
            client_ctx = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_ctx
            client_ctx.get.return_value = _mock_rdap_response(payload)
            return dns_lookup.invoke({"domain": domain})

    def test_extracts_registrant_org(self):
        """The main FP-fix change: registrant org is now surfaced."""
        payload = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["org", {}, "text", "Google LLC"],
                        ],
                    ],
                },
            ],
        }
        out = self._run(payload)
        assert "Registrant organization: Google LLC" in out

    def test_extracts_admin_and_tech_orgs(self):
        payload = {
            "entities": [
                {
                    "roles": ["administrative"],
                    "vcardArray": ["vcard", [["org", {}, "text", "Meta Platforms"]]],
                },
                {
                    "roles": ["technical"],
                    "vcardArray": ["vcard", [["org", {}, "text", "Cloudflare Inc"]]],
                },
            ],
        }
        out = self._run(payload)
        assert "Admin contact organization: Meta Platforms" in out
        assert "Tech contact organization: Cloudflare Inc" in out

    def test_returns_all_nameservers_not_just_three(self):
        """Previously capped at 3; ns1-4.google.com is a strong signal so
        we want the full list."""
        payload = {
            "nameservers": [
                {"ldhName": "ns1.google.com"},
                {"ldhName": "ns2.google.com"},
                {"ldhName": "ns3.google.com"},
                {"ldhName": "ns4.google.com"},
            ],
        }
        out = self._run(payload)
        for ns in ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"]:
            assert ns in out

    def test_preserves_registrar_and_dates(self):
        """Regression: the pre-existing fields (registrar, dates) must still work."""
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]],
                },
            ],
        }
        out = self._run(payload)
        assert "Registration date: 2020-01-15" in out
        assert "Expiration: 2030-01-15" in out
        assert "Registrar: MarkMonitor Inc." in out

    def test_full_google_shape(self):
        """End-to-end: the shape RDAP returns for a Google-owned domain
        must surface enough signal for the agent to conclude 'legit infra'."""
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "2013-06-01T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]],
                },
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["org", {}, "text", "Google LLC"]]],
                },
            ],
            "nameservers": [
                {"ldhName": "ns1.google.com"},
                {"ldhName": "ns2.google.com"},
                {"ldhName": "ns3.google.com"},
                {"ldhName": "ns4.google.com"},
            ],
        }
        out = self._run(payload, domain="adsensecustomsearchads.com")
        assert "Registrant organization: Google LLC" in out
        assert "ns1.google.com" in out and "ns4.google.com" in out

    def test_returns_message_when_no_data(self):
        out = self._run({})
        assert "no detailed RDAP data available" in out

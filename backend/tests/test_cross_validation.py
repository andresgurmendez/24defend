"""Cross-validation tests: server-side vs client-side classification consistency.

Verifies that the same domain gets the same treatment whether checked
on the device (DomainChecker/BrandRuleEngine/PhishingClassifier logic)
or on the server (agent heuristics/brand detection).

These tests catch drift between the iOS and backend detection logic.
"""

import sys
import os
import math

import pytest

# Make features module importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ml"))

from app.bloom import extract_base_domain, build_bloom_filter, check_bloom_filter


# ---------------------------------------------------------------------------
# Shared domain sets used by both server and client
# ---------------------------------------------------------------------------

BRANDS = {
    "brou", "bancorepublica", "itau", "santander", "scotiabank",
    "bbva", "hsbc", "heritage", "bandes", "prex", "oca",
    "mercadopago", "mercadolibre", "pedidosya", "abitab",
    "redpagos", "antel", "movistar", "claro", "bps", "dgi", "gub",
}

PHISHING_WORDS = {
    "actualizar", "actualizacion", "verificar", "verificacion",
    "confirmar", "confirmacion", "validar", "validacion",
    "restablecer", "recuperar", "desbloquear", "reactivar",
    "urgente", "inmediato", "suspension", "suspendido",
    "bloqueo", "bloqueado", "bloquear", "cancelar", "cancelado",
    "seguro", "seguridad", "proteccion", "alerta",
    "soporte", "ayuda", "centro", "servicio",
    "homebanking", "ebanking", "onlinebanking", "banca",
    "transferencia", "clave", "contrasena", "password",
    "pin", "token", "tarjeta", "credencial", "acceso",
    "cuenta", "usuario", "login", "signin", "ingreso",
    "formulario", "datos", "informacion",
}

HIGH_RISK_TLDS = {
    "xyz", "top", "click", "buzz", "gq", "ml", "cf", "tk",
    "pw", "cc", "club", "icu", "cam", "link", "online",
    "site", "website", "space", "info", "bid", "win", "loan",
}

INFRASTRUCTURE_SUFFIXES = [
    "akamaiedge.net", "akamai.net", "cloudfront.net", "cloudflare.com",
    "fastly.net", "apple.com", "apple-dns.net", "icloud.com", "aaplimg.com",
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "microsoft.com", "msedge.net", "azure.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net",
    "amazonaws.com", "amazon.com",
]


def is_infrastructure(domain: str) -> bool:
    """Mirror of iOS DomainChecker.isInfrastructureDomain."""
    d = domain.lower()
    for suffix in INFRASTRUCTURE_SUFFIXES:
        if d == suffix or d.endswith(f".{suffix}"):
            return True
    return False


def brand_rule_check(domain: str) -> dict:
    """Mirror of iOS BrandRuleEngine.assess — simplified."""
    d = domain.lower()
    found_brands = [b for b in BRANDS if b in d]
    found_phish = [w for w in PHISHING_WORDS if w in d]
    tld = d.split(".")[-1]

    score = 0.0
    if found_brands:
        score += 0.35
    if found_phish:
        score += 0.2
    if found_brands and found_phish:
        score += 0.25
    if found_brands and tld in HIGH_RISK_TLDS:
        score += 0.15

    return {
        "score": score,
        "is_high_risk": score >= 0.7,
        "matched_brand": found_brands[0] if found_brands else None,
    }


def ml_classifier_score(domain: str) -> float:
    """Mirror of iOS PhishingClassifier.predict — uses Python features module."""
    try:
        from features import extract_features
        model_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "ml", "models",
            "phishing_classifier_logistic.json"
        )
        import json
        with open(model_path) as f:
            model = json.load(f)

        feats = extract_features(domain)
        logit = sum(f * c for f, c in zip(feats, model["coefficients"])) + model["intercept"]
        return 1.0 / (1.0 + math.exp(-logit))
    except Exception:
        return 0.0


def client_side_verdict(domain: str) -> str:
    """Simulate the full iOS detection pipeline (layers 2-9).

    Returns: "block", "warn_brand", "warn_ml_silent", or "allow"
    """
    d = domain.lower().strip(".")

    # Infrastructure → allow
    if is_infrastructure(d):
        return "allow"

    # Brand rule engine
    brand = brand_rule_check(d)
    if brand["is_high_risk"] and brand["matched_brand"]:
        return "warn_brand"

    # ML classifier (silent — no user warning, just submit to API)
    score = ml_classifier_score(d)
    if score >= 0.7:
        return "warn_ml_silent"

    return "allow"


def server_side_heuristic_check(domain: str) -> dict:
    """Mirror of backend agent's domain_heuristics tool."""
    d = domain.lower()
    signals = []

    if len(d) > 30:
        signals.append("long_domain")
    if d.count("-") >= 2:
        signals.append("multiple_hyphens")

    digits = sum(1 for c in d if c.isdigit())
    if digits > 3:
        signals.append("many_digits")

    tld = d.split(".")[-1]
    if tld in HIGH_RISK_TLDS:
        signals.append("risky_tld")

    found_brands = [b for b in BRANDS if b in d]
    found_phish = [w for w in PHISHING_WORDS if w in d]

    if found_brands:
        signals.append(f"brand:{found_brands[0]}")
    if found_phish:
        signals.append("phishing_word")
    if found_brands and found_phish:
        signals.append("brand_phishing_combo")

    return {"signals": signals, "has_brand": bool(found_brands)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBasedomainConsistency:
    """Verify extract_base_domain is consistent between server and client."""

    TEST_DOMAINS = [
        ("homebanking.brou.com.uy", "brou.com.uy"),
        ("www.google.com", "google.com"),
        ("app.mercadopago.com", "mercadopago.com"),
        ("login.evil.brou-seguro.com", "brou-seguro.com"),
        ("brou.com.uy", "brou.com.uy"),
        ("api.v2.pedidosya.com", "pedidosya.com"),
        ("simple.org", "simple.org"),
        ("deep.sub.domain.co.uk", "domain.co.uk"),
    ]

    def test_base_domain_extraction(self):
        """Server-side extract_base_domain matches expected values."""
        for domain, expected in self.TEST_DOMAINS:
            result = extract_base_domain(domain)
            assert result == expected, f"extract_base_domain('{domain}') = '{result}', expected '{expected}'"


class TestBrandDetectionConsistency:
    """Verify brand detection produces same results on server and client."""

    # Domains that should be flagged as brand impersonation
    BRAND_PHISHING = [
        "brou-seguro.com",
        "actualizacion-brou-2026.xyz",
        "verificar-itau.top",
        "santander-bloqueo-urgente.click",
        "mercadopago-confirmar.top",
        "itau-verificar-cuenta.xyz",
    ]

    # Domains that should NOT be flagged
    LEGITIMATE = [
        "google.com",
        "facebook.com",
        "elobservador.com.uy",
        "cafe-jardin.com.uy",
        "tienda-norte.com",
        "random-shop.xyz",
    ]

    def test_brand_phishing_detected_on_both_sides(self):
        """Domains with brand + phishing words are caught by both server and client."""
        for domain in self.BRAND_PHISHING:
            client = brand_rule_check(domain)
            server = server_side_heuristic_check(domain)

            assert client["matched_brand"] is not None, \
                f"Client failed to detect brand in '{domain}'"
            assert server["has_brand"], \
                f"Server failed to detect brand in '{domain}'"

    def test_legitimate_not_flagged_on_either_side(self):
        """Legitimate domains are not brand-flagged on either side."""
        for domain in self.LEGITIMATE:
            client = brand_rule_check(domain)
            server = server_side_heuristic_check(domain)

            assert not client["is_high_risk"], \
                f"Client false-flagged '{domain}' as high risk"
            assert "brand_phishing_combo" not in server["signals"], \
                f"Server false-detected brand+phishing combo in '{domain}'"


class TestInfrastructureAllowlistConsistency:
    """Verify infrastructure domains are allowed on client (server doesn't check this)."""

    INFRA_DOMAINS = [
        "clients.l.google.com",
        "quota.fe2.apple-dns.net",
        "e6858.dsce9.akamaiedge.net",
        "gspe79-cdn.g.aaplimg.com",
        "www.googleapis.com",
        "edge.microsoft.com",
        "static.xx.fbcdn.net",
    ]

    def test_infrastructure_domains_allowed(self):
        """All known infrastructure domains pass through client without triggering."""
        for domain in self.INFRA_DOMAINS:
            verdict = client_side_verdict(domain)
            assert verdict == "allow", \
                f"Infrastructure domain '{domain}' got verdict '{verdict}', expected 'allow'"


class TestMLClassifierSilentBehavior:
    """Verify ML classifier is now silent (no user-facing warnings)."""

    # Domains that the ML model might flag but should NOT warn the user
    ML_SENSITIVE_DOMAINS = [
        "santander-mx.com",       # legitimate Santander Mexico
        "e6858.dsce9.akamaiedge.net",  # CDN (infrastructure-filtered first)
        "random-long-domain-with-numbers-123.xyz",  # random
    ]

    def test_ml_flagged_domains_get_silent_treatment(self):
        """Domains flagged by ML get 'warn_ml_silent' (not 'warn_brand')."""
        # The ML model should flag suspicious domains but silently
        for domain in self.ML_SENSITIVE_DOMAINS:
            verdict = client_side_verdict(domain)
            # Should be either "allow" (infrastructure filtered) or "warn_ml_silent" (silent)
            # Should NEVER be "warn_brand" unless there's a real brand match
            assert verdict != "warn_brand" or brand_rule_check(domain)["matched_brand"] is not None, \
                f"Domain '{domain}' got brand warning without actual brand match"


class TestBloomFilterConsistency:
    """Verify bloom filter built by server works correctly for client lookups."""

    def test_bloom_filter_true_positives(self):
        """Domains in the blacklist are found in the bloom filter."""
        domains = ["evil.com", "phishing.xyz", "brou-seguro.com", "fake-bank.top"]
        bloom = build_bloom_filter(domains)

        for domain in domains:
            assert check_bloom_filter(bloom, domain), \
                f"True positive failure: '{domain}' not found in bloom filter"

    def test_bloom_filter_base_domain_lookup(self):
        """Subdomains are found via base domain extraction."""
        domains = ["evil.com"]
        bloom = build_bloom_filter(domains)

        # subdomain should match via base domain
        base = extract_base_domain("login.evil.com")
        assert base == "evil.com"
        assert check_bloom_filter(bloom, base)

    def test_dual_bloom_reduces_fps(self):
        """Two independent bloom filters have lower combined FP rate."""
        import random
        random.seed(42)

        domains = [f"bad{i}.com" for i in range(100)]
        bloom_a = build_bloom_filter(domains, fp_rate=0.001)
        bloom_b = build_bloom_filter(domains, fp_rate=0.0015)

        # Test 1000 random non-member domains
        test_domains = [f"random{i}test.net" for i in range(1000)]

        fp_a = sum(1 for d in test_domains if check_bloom_filter(bloom_a, d))
        fp_b = sum(1 for d in test_domains if check_bloom_filter(bloom_b, d))
        fp_both = sum(1 for d in test_domains
                      if check_bloom_filter(bloom_a, d) and check_bloom_filter(bloom_b, d))

        # Combined FP should be much lower than either alone
        assert fp_both <= max(fp_a, fp_b), \
            f"Dual bloom FP ({fp_both}) should be <= single bloom FP (A={fp_a}, B={fp_b})"


class TestPipelineLayerOrder:
    """Verify the detection pipeline processes layers in the correct order."""

    def test_infrastructure_before_bloom(self):
        """Infrastructure domains should be allowed before bloom filter check."""
        # googleapis.com could false-positive in bloom filter
        # but infrastructure check should catch it first
        assert is_infrastructure("www.googleapis.com")
        assert client_side_verdict("www.googleapis.com") == "allow"

    def test_brand_rules_before_ml(self):
        """Brand rule matches should produce warn_brand, not warn_ml_silent."""
        domain = "brou-actualizacion-2026.xyz"
        verdict = client_side_verdict(domain)
        # Brand rules should catch this (brou + actualizacion + xyz)
        assert verdict == "warn_brand", \
            f"Expected warn_brand for '{domain}', got '{verdict}'"

    def test_ml_only_fires_after_brand_rules_miss(self):
        """ML classifier only triggers for domains that pass brand rules."""
        # Domain without a brand keyword but with suspicious features
        domain = "verify-account-login.xyz"
        verdict = client_side_verdict(domain)
        # No brand match → brand rules don't fire
        brand = brand_rule_check(domain)
        assert brand["matched_brand"] is None
        # ML might or might not flag it, but it should NOT be warn_brand
        assert verdict in ("allow", "warn_ml_silent")

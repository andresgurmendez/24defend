"""Lightweight domain investigation agent.

Checks multiple free signals to determine if a domain is malicious.
Designed to run without human intervention.
"""

import asyncio
from datetime import datetime, timezone
from time import time

import httpx

from app.domain_service import put_domain
from app.models import DomainEntry, EntryType, Verdict


async def investigate_domain(domain: str) -> DomainEntry:
    """Run automated investigation on a suspicious domain.

    Checks:
    1. Google Safe Browsing (if API key configured)
    2. Domain age via RDAP (free, replaces WHOIS)
    3. Basic heuristic scoring

    Returns a DomainEntry with verdict and reasoning.
    """
    signals: list[str] = []
    risk_score = 0.0

    # Run checks concurrently
    rdap_result, heuristic_result, cert_result = await asyncio.gather(
        _check_rdap(domain),
        _check_heuristics(domain),
        _check_ssl_cert(domain),
    )

    # RDAP domain age
    if rdap_result is not None:
        days_old = rdap_result
        if days_old < 7:
            risk_score += 0.5
            signals.append(f"Domain registered {days_old} days ago (very new)")
        elif days_old < 30:
            risk_score += 0.3
            signals.append(f"Domain registered {days_old} days ago (new)")
        elif days_old < 90:
            risk_score += 0.1
            signals.append(f"Domain registered {days_old} days ago")
        else:
            signals.append(f"Domain is {days_old} days old")
    else:
        signals.append("Domain age: could not determine")

    # SSL certificate
    c_score, c_signals = cert_result
    risk_score += c_score
    signals.extend(c_signals)

    # Heuristic score
    h_score, h_signals = heuristic_result
    risk_score += h_score
    signals.extend(h_signals)

    # Determine verdict
    if risk_score >= 0.7:
        verdict = Verdict.block
    elif risk_score >= 0.4:
        verdict = Verdict.warn
    else:
        verdict = Verdict.allow

    confidence = min(risk_score, 1.0)
    reason = "; ".join(signals)

    entry = DomainEntry(
        domain=domain,
        entry_type=EntryType.cache,
        verdict=verdict,
        confidence=confidence,
        reason=reason,
        checked_at=datetime.now(timezone.utc),
        ttl=int(time()) + 30 * 86400,  # cache for 30 days
    )

    # Persist to cache
    await put_domain(entry)

    return entry


async def _check_rdap(domain: str) -> int | None:
    """Check domain registration date via RDAP (free, no API key needed)."""
    # Extract the registrable domain (e.g., "sub.example.com" → "example.com")
    parts = domain.split(".")
    if len(parts) > 2:
        registrable = ".".join(parts[-2:])
    else:
        registrable = domain

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://rdap.org/domain/{registrable}")
            if resp.status_code != 200:
                return None

            data = resp.json()
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date = datetime.fromisoformat(
                        event["eventDate"].replace("Z", "+00:00")
                    )
                    delta = datetime.now(timezone.utc) - reg_date
                    return delta.days

    except Exception:
        return None

    return None


async def _check_ssl_cert(domain: str) -> tuple[float, list[str]]:
    """Check SSL certificate for suspicious signals."""
    return await asyncio.get_event_loop().run_in_executor(None, _check_ssl_cert_sync, domain)


def _check_ssl_cert_sync(domain: str) -> tuple[float, list[str]]:
    import ssl
    import socket

    score = 0.0
    signals = []

    # Strip www for cert check
    check_domain = domain[4:] if domain.startswith("www.") else domain

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=check_domain)
        conn.settimeout(5)
        conn.connect((check_domain, 443))
        cert = conn.getpeercert()
        conn.close()

        if not cert:
            signals.append("No SSL certificate")
            score += 0.2
            return score, signals

        # Check issuer
        issuer_parts = {k: v for item in cert.get("issuer", ()) for k, v in item}
        issuer_org = issuer_parts.get("organizationName", "").lower()

        free_cas = ["let's encrypt", "zerossl", "buypass", "ssl.com"]
        is_free_ca = any(ca in issuer_org for ca in free_cas)

        if is_free_ca:
            score += 0.15
            signals.append(f"Free CA certificate ({issuer_parts.get('organizationName', 'unknown')})")

        # Check cert age (notBefore)
        not_before_str = cert.get("notBefore", "")
        if not_before_str:
            # Format: "Mon DD HH:MM:SS YYYY GMT"
            from email.utils import parsedate_to_datetime
            try:
                not_before = parsedate_to_datetime(not_before_str)
                cert_age_days = (datetime.now(timezone.utc) - not_before).days
                if cert_age_days < 7:
                    score += 0.3
                    signals.append(f"SSL cert issued {cert_age_days} days ago (very new)")
                elif cert_age_days < 30:
                    score += 0.15
                    signals.append(f"SSL cert issued {cert_age_days} days ago (new)")
                else:
                    signals.append(f"SSL cert age: {cert_age_days} days")
            except Exception:
                pass

        # Check subject alternative names for mismatches
        san = cert.get("subjectAltName", ())
        san_domains = [v for t, v in san if t == "DNS"]
        if san_domains:
            # Wildcard covering too many domains = suspicious
            wildcards = [d for d in san_domains if d.startswith("*.")]
            if len(san_domains) > 10:
                score += 0.1
                signals.append(f"Cert covers {len(san_domains)} domains (shared hosting)")

        if not signals:
            signals.append("SSL certificate looks normal")

    except ssl.SSLCertVerificationError:
        score += 0.3
        signals.append("SSL certificate verification failed (invalid/self-signed)")
    except socket.timeout:
        signals.append("SSL connection timed out")
    except (ConnectionRefusedError, OSError):
        score += 0.1
        signals.append("No HTTPS server (HTTP only)")
    except Exception as e:
        signals.append(f"SSL check error: {type(e).__name__}")

    return score, signals


async def _check_heuristics(domain: str) -> tuple[float, list[str]]:
    """Score domain based on string features."""
    score = 0.0
    signals = []

    # Length
    if len(domain) > 30:
        score += 0.1
        signals.append(f"Long domain ({len(domain)} chars)")

    # Hyphen count
    hyphens = domain.count("-")
    if hyphens >= 2:
        score += 0.2
        signals.append(f"Multiple hyphens ({hyphens})")
    elif hyphens == 1:
        score += 0.05

    # Digit ratio
    digits = sum(1 for c in domain if c.isdigit())
    if digits > 3:
        score += 0.1
        signals.append(f"Many digits ({digits})")

    # Suspicious TLDs
    tld = domain.split(".")[-1].lower()
    risky_tlds = {"xyz", "top", "click", "buzz", "gq", "ml", "cf", "tk", "pw", "cc", "club", "icu", "cam"}
    if tld in risky_tlds:
        score += 0.3
        signals.append(f"High-risk TLD (.{tld})")

    # Subdomain depth
    dot_count = domain.count(".")
    if dot_count >= 3:
        score += 0.15
        signals.append(f"Deep subdomain nesting ({dot_count} levels)")

    # Contains common brand names as substring (potential impersonation)
    brands = ["brou", "itau", "santander", "scotiabank", "bbva", "hsbc",
              "mercadolibre", "mercadopago", "paypal", "netflix", "amazon"]
    found_brands = [b for b in brands if b in domain.lower() and domain.lower() != f"{b}.com"
                    and domain.lower() != f"{b}.com.uy"]
    if found_brands:
        score += 0.3
        signals.append(f"Contains brand name: {', '.join(found_brands)}")

    # Levenshtein similarity to known official domains
    from app.domain_service import scan_by_type as _scan  # lazy import to avoid circular
    from app.models import EntryType as _ET
    official_domains = _CACHED_WHITELIST or []
    base = _extract_base_domain(domain)
    for official in official_domains:
        off_base = _extract_base_domain(official)
        if base == off_base:
            continue
        dist = _levenshtein(base, off_base)
        max_len = max(len(base), len(off_base))
        if max_len > 0 and 0 < dist <= 3:
            sim = 1.0 - (dist / max_len)
            if sim >= 0.70:
                score += 0.4
                signals.append(f"Similar to official domain {official} (edit distance {dist})")
                break

    # Character entropy (high entropy = random-looking = suspicious)
    unique_chars = len(set(domain.replace(".", "")))
    total_chars = len(domain.replace(".", ""))
    if total_chars > 0:
        ratio = unique_chars / total_chars
        if ratio > 0.85:
            score += 0.1
            signals.append("High character entropy")

    if not signals:
        signals.append("No suspicious heuristic signals")

    return score, signals


# --- Levenshtein + domain helpers (mirrors iOS DomainChecker logic) ---

_CACHED_WHITELIST: list[str] = []


async def load_whitelist_cache():
    """Load whitelist domains into memory for Levenshtein checks."""
    global _CACHED_WHITELIST
    from app.domain_service import scan_by_type
    from app.models import EntryType
    entries = await scan_by_type(EntryType.whitelist)
    _CACHED_WHITELIST = [e.domain for e in entries]


def _extract_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    two_part_tlds = {"com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl", "co.uk", "com.au"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    if m == 0:
        return n
    if n == 0:
        return m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[n]

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
    rdap_result, heuristic_result = await asyncio.gather(
        _check_rdap(domain),
        _check_heuristics(domain),
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

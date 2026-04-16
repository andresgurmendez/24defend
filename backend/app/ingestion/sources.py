"""Public threat intelligence feed ingestion.

Layer 1 — Global public sources (free, day-one value):
  - PhishTank: community-verified phishing URLs
  - OpenPhish: academic phishing detection
  - URLhaus (abuse.ch): active phishing/malware domains
  - Phishing.Army: curated DNS blocklist

Layer 2 — Regional LatAm (requires agreements, future):
  - CERTuy, CERT.br, LACNIC CSIRT

Layer 3 — Proprietary (built over time):
  - Institution reports, user reports, honeypots

Whitelist auto-discovery:
  - Certificate Transparency logs via crt.sh
"""

import asyncio
import csv
import io
import json
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)


async def fetch_phishtank() -> list[str]:
    """Fetch verified phishing URLs from PhishTank.

    Returns list of domains (extracted from full URLs).
    Free, updated hourly. JSON feed.
    """
    url = "http://data.phishtank.com/data/online-valid.json.bz2"
    # PhishTank also offers a simpler CSV; use the online-valid CSV for simplicity
    csv_url = "http://data.phishtank.com/data/online-valid.csv"

    domains = set()
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(csv_url, follow_redirects=True)
            if resp.status_code != 200:
                logger.warning(f"PhishTank returned {resp.status_code}")
                return []

            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                url_str = row.get("url", "")
                domain = _extract_domain(url_str)
                if domain:
                    domains.add(domain)

        logger.info(f"PhishTank: {len(domains)} unique domains")
    except Exception as e:
        logger.error(f"PhishTank fetch failed: {e}")

    return list(domains)


async def fetch_openphish() -> list[str]:
    """Fetch phishing URLs from OpenPhish (free tier).

    Simple text file, one URL per line.
    """
    url = "https://openphish.com/feed.txt"
    domains = set()

    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning(f"OpenPhish returned {resp.status_code}")
                return []

            for line in resp.text.strip().split("\n"):
                domain = _extract_domain(line.strip())
                if domain:
                    domains.add(domain)

        logger.info(f"OpenPhish: {len(domains)} unique domains")
    except Exception as e:
        logger.error(f"OpenPhish fetch failed: {e}")

    return list(domains)


async def fetch_urlhaus() -> list[str]:
    """Fetch active malware/phishing domains from URLhaus (abuse.ch).

    CSV feed, updated every 5 minutes. Free for non-commercial use.
    """
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    domains = set()

    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning(f"URLhaus returned {resp.status_code}")
                return []

            for line in resp.text.split("\n"):
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split('","')
                if len(parts) >= 3:
                    url_str = parts[2].strip('"')
                    domain = _extract_domain(url_str)
                    if domain:
                        domains.add(domain)

        logger.info(f"URLhaus: {len(domains)} unique domains")
    except Exception as e:
        logger.error(f"URLhaus fetch failed: {e}")

    return list(domains)


async def fetch_phishing_army() -> list[str]:
    """Fetch Phishing.Army DNS blocklist.

    Plain text, one domain per line. Designed for DNS blocking.
    """
    url = "https://phishing.army/download/phishing_army_blocklist.txt"
    domains = set()

    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning(f"Phishing.Army returned {resp.status_code}")
                return []

            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())

        logger.info(f"Phishing.Army: {len(domains)} unique domains")
    except Exception as e:
        logger.error(f"Phishing.Army fetch failed: {e}")

    return list(domains)


async def fetch_crtsh_subdomains(root_domain: str) -> list[str]:
    """Discover subdomains via Certificate Transparency logs (crt.sh).

    Used for auto-building whitelists from a partner's root domain.
    Free, no API key needed.
    """
    url = f"https://crt.sh/?q=%.{root_domain}&output=json"
    subdomains = set()

    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning(f"crt.sh returned {resp.status_code} for {root_domain}")
                return []

            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for subdomain in name.split("\n"):
                    subdomain = subdomain.strip().lower()
                    if subdomain and not subdomain.startswith("*"):
                        subdomains.add(subdomain)

        logger.info(f"crt.sh: {len(subdomains)} subdomains for {root_domain}")
    except Exception as e:
        logger.error(f"crt.sh fetch failed for {root_domain}: {e}")

    return list(subdomains)


async def fetch_all_blacklists() -> dict[str, list[str]]:
    """Fetch all public blacklist sources concurrently.

    Returns dict of source_name → list of domains.
    """
    results = await asyncio.gather(
        fetch_openphish(),
        fetch_phishing_army(),
        fetch_urlhaus(),
        # PhishTank often rate-limits; try but don't block on it
        fetch_phishtank(),
        return_exceptions=True,
    )

    sources = {}
    names = ["openphish", "phishing_army", "urlhaus", "phishtank"]

    for name, result in zip(names, results):
        if isinstance(result, Exception):
            logger.error(f"{name} failed: {result}")
            sources[name] = []
        else:
            sources[name] = result

    total = sum(len(v) for v in sources.values())
    logger.info(f"Total unique domains across all sources: {total}")

    return sources


def _extract_domain(url: str) -> str | None:
    """Extract domain from a full URL."""
    url = url.strip()
    if not url:
        return None

    # Remove protocol
    for prefix in ("https://", "http://", "//"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break

    # Remove path, query, fragment
    domain = url.split("/")[0].split("?")[0].split("#")[0]

    # Remove port
    domain = domain.split(":")[0]

    domain = domain.lower().strip(".")

    if not domain or "." not in domain:
        return None

    return domain

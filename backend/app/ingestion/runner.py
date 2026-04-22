"""Ingestion runner — orchestrates fetching, deduplication, and storage."""

import logging
from datetime import datetime, timezone

from app.bloom import extract_base_domain
from app.domain_service import lookup_domain, put_domains_bulk
from app.ingestion.sources import fetch_all_blacklists, fetch_crtsh_subdomains
from app.models import EntryType

logger = logging.getLogger(__name__)

# Domains that serve millions of users and shouldn't be blocked at the domain
# level even if one malicious URL was hosted there.  Blocking these at DNS
# breaks legitimate pages.
SHARED_INFRASTRUCTURE_DOMAINS = {
    # Ad networks / ad tech
    "adnxs.com", "adsrvr.org", "demdex.net", "rubiconproject.com",
    "pubmatic.com", "criteo.com", "taboola.com", "outbrain.com",
    "moatads.com", "quantserve.com", "2mdn.net", "serving-sys.com",
    "googlesyndication.com", "googleadservices.com",
    # CDNs / shared hosting
    "akamai.net", "akamaiedge.net", "cloudflare.com", "fastly.net",
    "amazonaws.com", "cloudfront.net", "azurefd.net", "edgekey.net",
    # Analytics / tracking
    "google-analytics.com", "googletagmanager.com", "hotjar.com",
    "segment.io", "mixpanel.com", "amplitude.com",
    # Social / major platforms
    "facebook.com", "fbcdn.net", "twitter.com", "instagram.com",
    "youtube.com", "tiktok.com", "linkedin.com", "reddit.com",
    "whatsapp.net", "telegram.org",
    # Major services
    "google.com", "googleapis.com", "gstatic.com", "apple.com",
    "microsoft.com", "amazon.com", "netflix.com", "spotify.com",
    "yahoo.com", "yimg.com",
    "github.com", "stackoverflow.com", "wikipedia.org",
    # Payment / fintech (should never be blacklisted at domain level)
    "paypal.com", "stripe.com", "shopify.com",
}


async def _fetch_popular_domains() -> set[str]:
    """Download Majestic Million top 100K domains to filter shared infrastructure.

    Any domain in the top 100K is too popular to block at the DNS level —
    it serves millions of legitimate users even if one malicious URL was hosted there.
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get("https://downloads.majestic.com/majestic_million.csv")
            if resp.status_code != 200:
                logger.warning(f"Majestic Million returned {resp.status_code}, falling back to hardcoded list")
                return SHARED_INFRASTRUCTURE_DOMAINS

            popular = set()
            for i, line in enumerate(resp.text.strip().split("\n")):
                if i == 0:
                    continue  # skip header
                if i > 100000:
                    break
                parts = line.split(",")
                if len(parts) >= 3:
                    popular.add(parts[2].lower().strip())

            logger.info(f"Loaded {len(popular)} popular domains from Majestic Million")
            return popular

    except Exception as e:
        logger.warning(f"Failed to fetch Majestic Million: {e}, falling back to hardcoded list")
        return SHARED_INFRASTRUCTURE_DOMAINS


async def run_blacklist_ingestion() -> dict:
    """Fetch all public blacklist sources and store new domains.

    Filters out popular/shared-infrastructure domains that shouldn't
    be blocked at the DNS level.
    """
    # Fetch threat feeds and popular domain list in parallel
    import asyncio
    sources_task = fetch_all_blacklists()
    popular_task = _fetch_popular_domains()
    sources, popular_domains = await asyncio.gather(sources_task, popular_task)

    # Deduplicate across all sources
    all_domains: set[str] = set()
    for domains in sources.values():
        all_domains.update(domains)

    logger.info(f"Total unique domains across all sources: {len(all_domains)}")

    # Filter out popular/shared-infrastructure domains
    # A domain in Majestic top 100K serves millions of users — blocking it
    # at DNS level breaks pages without meaningful phishing protection
    before_filter = len(all_domains)
    all_domains = {
        d for d in all_domains
        if extract_base_domain(d) not in popular_domains
    }
    filtered_count = before_filter - len(all_domains)
    if filtered_count:
        logger.info(
            f"Filtered {filtered_count} popular/shared-infrastructure domains "
            f"(Majestic top 100K + hardcoded list)"
        )

    # Skip dedup on large batches — DynamoDB batch_writer handles overwrites
    # Checking 28K domains one-by-one takes minutes and isn't worth it
    # for idempotent blacklist entries
    new_domains = list(all_domains)
    logger.info(f"Domains to upsert: {len(new_domains)} (skipping individual dedup for performance)")

    if new_domains:
        # Batch insert in chunks of 25 (DynamoDB batch limit)
        chunk_size = 25
        total_added = 0
        for i in range(0, len(new_domains), chunk_size):
            chunk = new_domains[i:i + chunk_size]
            added = await put_domains_bulk(
                domains=chunk,
                entry_type=EntryType.blacklist,
                reason="Public threat feed",
            )
            total_added += added

        logger.info(f"Added {total_added} new blacklist domains")
    else:
        total_added = 0

    stats = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sources": {name: len(domains) for name, domains in sources.items()},
        "total_unique": len(all_domains),
        "new_added": total_added,
        "already_known": len(all_domains) - len(new_domains),
    }

    return stats


async def run_whitelist_discovery(root_domain: str, partner_id: str) -> dict:
    """Auto-discover subdomains for a partner's root domain via CT logs.

    Stores discovered subdomains as whitelist entries.
    """
    subdomains = await fetch_crtsh_subdomains(root_domain)

    if not subdomains:
        return {"root_domain": root_domain, "discovered": 0, "new_added": 0}

    # Filter out already-known domains
    new_domains = []
    for domain in subdomains:
        existing = await lookup_domain(domain)
        if not existing:
            new_domains.append(domain)

    if new_domains:
        added = await put_domains_bulk(
            domains=new_domains,
            entry_type=EntryType.whitelist,
            partner_id=partner_id,
            reason=f"Auto-discovered via CT logs for {root_domain}",
        )
    else:
        added = 0

    stats = {
        "root_domain": root_domain,
        "discovered": len(subdomains),
        "new_added": added,
        "already_known": len(subdomains) - len(new_domains),
    }

    logger.info(f"Whitelist discovery for {root_domain}: {stats}")
    return stats

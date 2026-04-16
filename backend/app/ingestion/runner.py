"""Ingestion runner — orchestrates fetching, deduplication, and storage."""

import logging
from datetime import datetime, timezone

from app.domain_service import lookup_domain, put_domains_bulk
from app.ingestion.sources import fetch_all_blacklists, fetch_crtsh_subdomains
from app.models import EntryType

logger = logging.getLogger(__name__)


async def run_blacklist_ingestion() -> dict:
    """Fetch all public blacklist sources and store new domains.

    Skips domains already in DynamoDB (blacklist, whitelist, or cache).
    Returns stats about what was ingested.
    """
    sources = await fetch_all_blacklists()

    # Deduplicate across all sources
    all_domains: set[str] = set()
    for domains in sources.values():
        all_domains.update(domains)

    logger.info(f"Total unique domains across all sources: {len(all_domains)}")

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

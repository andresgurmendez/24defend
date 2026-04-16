"""Admin endpoints for managing blacklists, whitelists, and bloom filters."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from pydantic import BaseModel

from app.auth import require_api_key
from app.bloom import generate_bloom_filters
from app.domain_service import delete_domain, put_domains_bulk, scan_by_type
from app.ingestion.runner import run_blacklist_ingestion, run_whitelist_discovery
from app.models import BulkAddRequest, DomainEntry, EntryType
from app.scheduler import (
    BLACKLIST_FILENAME,
    WHITELIST_FILENAME,
    generate_and_store_bloom_filters,
    read_bloom_file,
)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_api_key)])


@router.post("/domains")
async def add_domains(req: BulkAddRequest) -> dict:
    """Bulk add domains to blacklist or whitelist."""
    count = await put_domains_bulk(
        domains=req.domains,
        entry_type=req.entry_type,
        partner_id=req.partner_id,
        reason=req.reason,
    )
    return {"added": count, "entry_type": req.entry_type.value}


@router.delete("/domains/{domain}")
async def remove_domain(domain: str) -> dict:
    """Remove a domain from any list."""
    await delete_domain(domain)
    return {"deleted": domain}


@router.get("/domains", response_model=list[DomainEntry])
async def list_domains(entry_type: EntryType, partner_id: str | None = None) -> list[DomainEntry]:
    """List all domains of a given type."""
    return await scan_by_type(entry_type, partner_id)


class WhitelistDiscoveryRequest(BaseModel):
    root_domain: str
    partner_id: str


@router.post("/ingest/blacklists")
async def ingest_blacklists() -> dict:
    """Fetch all public threat feeds and add new domains to blacklist.

    Sources: OpenPhish, PhishTank, URLhaus, Phishing.Army
    """
    return await run_blacklist_ingestion()


@router.post("/ingest/whitelist-discovery")
async def discover_whitelist(req: WhitelistDiscoveryRequest) -> dict:
    """Auto-discover subdomains for a partner via Certificate Transparency logs.

    Provide the root domain (e.g., brou.com.uy) and partner ID.
    """
    return await run_whitelist_discovery(req.root_domain, req.partner_id)


@router.get("/bloom-filter/whitelist")
async def get_whitelist_bloom() -> Response:
    """Bloom filter of known-safe base domains (served from disk).

    On-device: if domain's base matches → allow silently, skip all checks.
    Contains only base/registrable domains, not subdomains.
    """
    data = read_bloom_file(WHITELIST_FILENAME)
    if data is None:
        raise HTTPException(status_code=503, detail="Whitelist bloom filter not yet generated")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=whitelist.bloom"},
    )


@router.get("/bloom-filter/blacklist")
async def get_blacklist_bloom() -> Response:
    """Bloom filter of known-bad base domains (served from disk).

    On-device: if domain's base matches → block immediately, no API call.
    Contains only base/registrable domains, not subdomains.
    """
    data = read_bloom_file(BLACKLIST_FILENAME)
    if data is None:
        raise HTTPException(status_code=503, detail="Blacklist bloom filter not yet generated")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=blacklist.bloom"},
    )


@router.get("/model/classifier")
async def get_classifier_weights() -> dict:
    """Serve the on-device phishing classifier weights.

    The iOS app downloads this on launch and caches it.
    ~200 bytes JSON — coefficients + intercept for logistic regression.
    """
    import json
    import os

    # Serve from disk if available (generated during training)
    model_path = os.path.join(settings.bloom_dir, "phishing_classifier.json")
    if os.path.exists(model_path):
        with open(model_path) as f:
            return json.load(f)

    # Fallback: hardcoded current weights
    return {
        "version": 1,
        "type": "logistic_regression",
        "feature_names": [
            "domain_length", "name_length", "dot_count", "hyphen_count",
            "digit_count", "digit_ratio", "unique_char_ratio", "consonant_ratio",
            "max_consecutive_consonants", "has_brand", "brand_count",
            "has_phishing_word", "phishing_word_count", "brand_phishing_combo",
            "has_year_pattern", "brand_year_combo", "tld_risk",
            "brand_on_risky_tld", "has_homoglyph", "subdomain_depth",
        ],
        "coefficients": [
            0.1515754896293396, -0.17687062190652342, 0.4251215061805213,
            0.6522107335346615, 8.720099093690225, 1.168831306654816,
            1.6534057467548318, 0.48358291642889606, 1.0413817120788775,
            2.2560370434233863, 2.52623892330409, -1.481912543680876,
            0.5269276493085449, 1.8739844777853785, 0.012820477554654004,
            0.012820477554654004, 4.674802613911455, 2.0929952382316026,
            1.9273927957533727, 0.9272854399688297,
        ],
        "intercept": -11.079669393324433,
    }


@router.get("/bloom-filter/stats")
async def get_bloom_stats() -> dict:
    """Stats about both bloom filters without downloading them."""
    result = await generate_bloom_filters()
    return {
        "whitelist": {
            "total_entries": result["whitelist"]["total_entries"],
            "unique_base_domains": result["whitelist"]["unique_base_domains"],
            "bloom_size_bytes": result["whitelist"]["bloom_size_bytes"],
        },
        "blacklist": {
            "total_entries": result["blacklist"]["total_entries"],
            "unique_base_domains": result["blacklist"]["unique_base_domains"],
            "bloom_size_bytes": result["blacklist"]["bloom_size_bytes"],
        },
    }


@router.post("/bloom-filter/regenerate")
async def regenerate_bloom_filters() -> dict:
    """Manually trigger bloom filter regeneration and write to disk."""
    stats = await generate_and_store_bloom_filters()
    return {"status": "ok", **stats}


@router.post("/jobs/run-daily")
async def run_daily_job() -> dict:
    """Manually trigger the full daily job (ingestion + bloom regeneration)."""
    ingestion_stats = await run_blacklist_ingestion()
    bloom_stats = await generate_and_store_bloom_filters()
    return {
        "status": "ok",
        "ingestion": ingestion_stats,
        "bloom": bloom_stats,
    }

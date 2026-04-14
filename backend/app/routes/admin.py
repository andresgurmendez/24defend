"""Admin endpoints for managing blacklists, whitelists, and bloom filters."""

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from app.auth import require_api_key
from app.bloom import generate_bloom_filter
from app.domain_service import delete_domain, put_domains_bulk, scan_by_type
from app.models import BulkAddRequest, DomainEntry, EntryType

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


@router.get("/bloom-filter")
async def get_bloom_filter() -> Response:
    """Generate and return the current bloom filter as binary data.

    The iOS app fetches this periodically for on-device checks.
    """
    data = await generate_bloom_filter()
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=bloomfilter.bin"},
    )

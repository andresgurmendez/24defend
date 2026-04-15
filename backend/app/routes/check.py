"""Domain check endpoint — called by the iOS app for suspicious domains."""

from fastapi import APIRouter

from app.investigation.graph import investigate_domain
from app.domain_service import lookup_domain
from app.models import DomainCheckRequest, DomainCheckResponse, EntryType, Verdict

router = APIRouter(tags=["check"])


@router.post("/check", response_model=DomainCheckResponse)
async def check_domain(req: DomainCheckRequest):
    """Check a domain against the database, run agent if unknown.

    Flow:
    1. Look up in DynamoDB (blacklist, whitelist, or cached verdict)
    2. If found → return immediately
    3. If not found → run agent investigation → cache result → return
    """
    domain = req.domain.lower().strip(".")

    # 1. Direct lookup — try exact match, then strip www, then walk up parent domains
    candidates = [domain]
    if domain.startswith("www."):
        candidates.append(domain[4:])
    # Also check parent domains (e.g., "sub.evil.com" → "evil.com")
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        candidates.append(".".join(parts[i:]))

    entry = None
    for candidate in candidates:
        entry = await lookup_domain(candidate)
        if entry:
            break

    if entry:
        if entry.entry_type == EntryType.blacklist:
            return DomainCheckResponse(
                domain=domain,
                verdict=Verdict.block,
                reason=entry.reason or "Known phishing domain",
                confidence=1.0,
                source="blacklist",
            )

        if entry.entry_type == EntryType.whitelist:
            return DomainCheckResponse(
                domain=domain,
                verdict=Verdict.allow,
                reason=f"Verified domain (partner: {entry.partner_id or 'unknown'})",
                confidence=1.0,
                source="whitelist",
            )

        if entry.entry_type == EntryType.cache and entry.verdict:
            return DomainCheckResponse(
                domain=domain,
                verdict=entry.verdict,
                reason=entry.reason or "Previously investigated",
                confidence=entry.confidence or 0.5,
                source="cache",
            )

    # 2. Not found — investigate
    result = await investigate_domain(domain)

    return DomainCheckResponse(
        domain=domain,
        verdict=result.verdict or Verdict.allow,
        reason=result.reason or "Investigated by agent",
        confidence=result.confidence or 0.5,
        source="agent",
    )

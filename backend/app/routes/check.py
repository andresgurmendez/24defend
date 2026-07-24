"""Domain check endpoint — called by the iOS app for suspicious domains."""

from fastapi import APIRouter

from app.investigation.graph import investigate_domain
from app.domain_service import lookup_domain
from app.models import DomainCheckRequest, DomainCheckResponse, EntryType, Verdict
from app.popular_domains import get_instance as get_popular_domains

router = APIRouter(tags=["check"])


@router.post("/check", response_model=DomainCheckResponse)
async def check_domain(req: DomainCheckRequest):
    """Check a domain against the database, run agent if unknown.

    Flow:
    1. Popular-domain override — if the eTLD+1 is in Majestic top 1M or in
       our curated vendor list, return allow immediately. This runs BEFORE
       the DB lookup so a mistakenly-listed popular domain (e.g. PhishTank
       once flagged pokeapi.co) can never win over its reputation.
    2. DB lookup (whitelist / blacklist / cache).
    3. Agent investigation if nothing else matched.
    """
    domain = req.domain.lower().strip(".")

    # 1. Popular-domain override — highest-precedence allow.
    # A domain popular enough to sit in Majestic top 1M is very unlikely to be
    # phishing, and even if it were legitimately compromised, blocking at DNS
    # level is the wrong tool (would nuke the whole site). Threat feeds
    # occasionally misclassify these (e.g. PhishTank tagging pokeapi.co with
    # target=Other) — this override is the safety net.
    if get_popular_domains().is_popular(domain):
        return DomainCheckResponse(
            domain=domain, verdict=Verdict.allow,
            reason="Dominio de infraestructura popular",
            confidence=1.0, source="popular",
        )

    # 2. Direct lookup — try exact match, then strip www, then walk up parent domains
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
                should_notify=True,  # threat intel confirmed — always notify
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
                should_notify=entry.should_notify,
            )

    # 3. Not found — investigate
    result = await investigate_domain(domain)

    return DomainCheckResponse(
        domain=domain,
        verdict=result.verdict or Verdict.allow,
        reason=result.reason or "Investigated by agent",
        confidence=result.confidence or 0.5,
        source="agent",
        should_notify=result.should_notify,
    )

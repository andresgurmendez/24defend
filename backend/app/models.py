from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class EntryType(str, Enum):
    blacklist = "blacklist"
    whitelist = "whitelist"
    cache = "cache"


class Verdict(str, Enum):
    block = "block"
    warn = "warn"
    allow = "allow"


class DomainEntry(BaseModel):
    domain: str
    entry_type: EntryType
    partner_id: str | None = None       # for whitelist entries
    verdict: Verdict | None = None      # for cache entries
    confidence: float | None = None     # for cache entries
    reason: str | None = None           # human/agent-readable reason
    should_notify: bool = False         # agent recommends retroactive user notification
    checked_at: datetime | None = None
    ttl: int | None = None              # DynamoDB TTL (epoch seconds)


class DomainCheckRequest(BaseModel):
    domain: str


class DomainCheckResponse(BaseModel):
    domain: str
    verdict: Verdict
    reason: str
    confidence: float
    source: str  # "blacklist", "whitelist", "cache", "agent"
    should_notify: bool = False  # whether to send retroactive notification to user


class BulkAddRequest(BaseModel):
    domains: list[str]
    entry_type: EntryType
    partner_id: str | None = None
    reason: str | None = None

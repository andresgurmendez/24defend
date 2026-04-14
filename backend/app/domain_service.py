from datetime import datetime, timezone
from time import time

from app.db import get_table
from app.models import DomainEntry, EntryType, Verdict


async def lookup_domain(domain: str) -> DomainEntry | None:
    """Look up a domain in DynamoDB."""
    async with get_table() as table:
        resp = await table.get_item(Key={"domain": domain.lower()})
        item = resp.get("Item")
        if not item:
            return None
        return _item_to_entry(item)


async def put_domain(entry: DomainEntry) -> None:
    """Insert or update a domain entry."""
    item = {
        "domain": entry.domain.lower(),
        "entry_type": entry.entry_type.value,
    }
    if entry.partner_id:
        item["partner_id"] = entry.partner_id
    if entry.verdict:
        item["verdict"] = entry.verdict.value
    if entry.confidence is not None:
        item["confidence"] = str(entry.confidence)
    if entry.reason:
        item["reason"] = entry.reason
    if entry.checked_at:
        item["checked_at"] = entry.checked_at.isoformat()
    if entry.ttl:
        item["ttl"] = entry.ttl

    async with get_table() as table:
        await table.put_item(Item=item)


async def put_domains_bulk(domains: list[str], entry_type: EntryType,
                           partner_id: str | None = None,
                           reason: str | None = None) -> int:
    """Bulk insert domains."""
    async with get_table() as table:
        async with table.batch_writer() as batch:
            for domain in domains:
                item = {
                    "domain": domain.lower(),
                    "entry_type": entry_type.value,
                }
                if partner_id:
                    item["partner_id"] = partner_id
                if reason:
                    item["reason"] = reason
                if entry_type == EntryType.cache:
                    item["checked_at"] = datetime.now(timezone.utc).isoformat()
                    item["ttl"] = int(time()) + 30 * 86400  # 30 days
                await batch.put_item(Item=item)
    return len(domains)


async def delete_domain(domain: str) -> None:
    async with get_table() as table:
        await table.delete_item(Key={"domain": domain.lower()})


async def scan_by_type(entry_type: EntryType, partner_id: str | None = None) -> list[DomainEntry]:
    """Scan all entries of a given type. Fine for small datasets (<10K)."""
    async with get_table() as table:
        kwargs = {
            "FilterExpression": "entry_type = :t",
            "ExpressionAttributeValues": {":t": entry_type.value},
        }
        if partner_id:
            kwargs["FilterExpression"] += " AND partner_id = :p"
            kwargs["ExpressionAttributeValues"][":p"] = partner_id

        entries = []
        resp = await table.scan(**kwargs)
        entries.extend(_item_to_entry(i) for i in resp.get("Items", []))

        while "LastEvaluatedKey" in resp:
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            resp = await table.scan(**kwargs)
            entries.extend(_item_to_entry(i) for i in resp.get("Items", []))

        return entries


def _item_to_entry(item: dict) -> DomainEntry:
    return DomainEntry(
        domain=item["domain"],
        entry_type=EntryType(item["entry_type"]),
        partner_id=item.get("partner_id"),
        verdict=Verdict(item["verdict"]) if "verdict" in item else None,
        confidence=float(item["confidence"]) if "confidence" in item else None,
        reason=item.get("reason"),
        checked_at=datetime.fromisoformat(item["checked_at"]) if "checked_at" in item else None,
        ttl=int(item["ttl"]) if "ttl" in item else None,
    )

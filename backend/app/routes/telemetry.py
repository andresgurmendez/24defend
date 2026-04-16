"""Telemetry endpoints — anonymous event collection from devices."""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from time import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.db import get_table

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/telemetry", tags=["telemetry"])

MAX_EVENTS_PER_BATCH = 100


# ---------- Request / response models ----------


class TelemetryEvent(BaseModel):
    event_type: str  # "blocked", "warned", "false_positive_report"
    domain: str  # base domain only
    layer: str  # "bloom_blacklist", "brand_rules", "ml_classifier", "agent", "runtime_blacklist"
    verdict: str  # "block", "warn"
    timestamp: str  # ISO format from device

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        allowed = {"blocked", "warned", "false_positive_report"}
        if v not in allowed:
            raise ValueError(f"event_type must be one of {allowed}")
        return v

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        allowed = {"block", "warn"}
        if v not in allowed:
            raise ValueError(f"verdict must be one of {allowed}")
        return v


class SessionStats(BaseModel):
    total_queries: int = 0
    cache_hits: int = 0
    bloom_whitelist_hits: int = 0
    bloom_blacklist_hits: int = 0
    infrastructure_allowed: int = 0
    brand_rule_warns: int = 0
    ml_warns: int = 0
    api_calls: int = 0
    blocks: int = 0
    warns: int = 0
    period_seconds: int = 3600


class TelemetryBatch(BaseModel):
    events: list[TelemetryEvent]
    session_stats: SessionStats | None = None
    device_id: str | None = None  # anonymous UUID, optional

    @field_validator("events")
    @classmethod
    def validate_events_length(cls, v: list[TelemetryEvent]) -> list[TelemetryEvent]:
        if len(v) > MAX_EVENTS_PER_BATCH:
            raise ValueError(f"Maximum {MAX_EVENTS_PER_BATCH} events per batch")
        return v


# ---------- Endpoints ----------


@router.post("/events")
async def ingest_events(batch: TelemetryBatch) -> dict:
    """Accept a batch of telemetry events from a device. No auth required.

    Events are stored in the existing DynamoDB table with a special key format
    so they don't collide with domain entries:
      PK (domain) = "telemetry#<event_type>#<YYYY-MM-DD>"
      entry_type  = "event"
    This lets us query by event type + date efficiently.

    Session stats (if provided) are stored as a separate item:
      PK (domain) = "telemetry#session_stats#<YYYY-MM-DD>"
    """
    if not batch.events and not batch.session_stats:
        return {"accepted": 0}

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    items_written = 0

    try:
        async with get_table() as table:
            async with table.batch_writer() as writer:
                # Write individual events
                for event in batch.events:
                    event_id = uuid.uuid4().hex[:12]
                    pk = f"telemetry#{event.event_type}#{date_str}"

                    item = {
                        "domain": pk,
                        "entry_type": "event",
                        "event_id": event_id,
                        "event_type": event.event_type,
                        "event_domain": event.domain.lower(),
                        "layer": event.layer,
                        "verdict": event.verdict,
                        "device_timestamp": event.timestamp,
                        "server_timestamp": now.isoformat(),
                        "ttl": int(time()) + 90 * 86400,  # keep 90 days
                    }
                    if batch.device_id:
                        item["device_id"] = batch.device_id

                    await writer.put_item(Item=item)
                    items_written += 1

                # Write session stats as a single aggregated item
                if batch.session_stats:
                    stats = batch.session_stats
                    stats_id = uuid.uuid4().hex[:12]
                    pk = f"telemetry#session_stats#{date_str}"

                    item = {
                        "domain": pk,
                        "entry_type": "session_stats",
                        "stats_id": stats_id,
                        "total_queries": stats.total_queries,
                        "cache_hits": stats.cache_hits,
                        "bloom_whitelist_hits": stats.bloom_whitelist_hits,
                        "bloom_blacklist_hits": stats.bloom_blacklist_hits,
                        "infrastructure_allowed": stats.infrastructure_allowed,
                        "brand_rule_warns": stats.brand_rule_warns,
                        "ml_warns": stats.ml_warns,
                        "api_calls": stats.api_calls,
                        "blocks": stats.blocks,
                        "warns": stats.warns,
                        "period_seconds": stats.period_seconds,
                        "server_timestamp": now.isoformat(),
                        "ttl": int(time()) + 90 * 86400,
                    }
                    if batch.device_id:
                        item["device_id"] = batch.device_id

                    await writer.put_item(Item=item)
                    items_written += 1

    except Exception:
        logger.exception("Failed to write telemetry events")
        raise HTTPException(status_code=500, detail="Failed to store events")

    logger.info(f"Telemetry: accepted {items_written} items ({len(batch.events)} events)")
    return {"accepted": items_written}


@router.get("/stats")
async def get_stats() -> dict:
    """Return aggregate telemetry stats. Requires admin API key in production,
    but left open for now during development.

    Scans telemetry items and aggregates counts by event_type and layer.
    """
    try:
        async with get_table() as table:
            # Scan for all telemetry event items
            event_counts: dict[str, int] = defaultdict(int)
            layer_counts: dict[str, int] = defaultdict(int)
            domain_counts: dict[str, int] = defaultdict(int)
            total_events = 0
            total_session_reports = 0
            aggregate_stats = {
                "total_queries": 0,
                "cache_hits": 0,
                "bloom_whitelist_hits": 0,
                "bloom_blacklist_hits": 0,
                "infrastructure_allowed": 0,
                "brand_rule_warns": 0,
                "ml_warns": 0,
                "api_calls": 0,
                "blocks": 0,
                "warns": 0,
            }

            kwargs = {
                "FilterExpression": "begins_with(#d, :prefix)",
                "ExpressionAttributeNames": {"#d": "domain"},
                "ExpressionAttributeValues": {":prefix": "telemetry#"},
            }

            resp = await table.scan(**kwargs)
            items = resp.get("Items", [])

            while "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                resp = await table.scan(**kwargs)
                items.extend(resp.get("Items", []))

            for item in items:
                if item.get("entry_type") == "event":
                    total_events += 1
                    event_type = item.get("event_type", "unknown")
                    event_counts[event_type] += 1
                    layer = item.get("layer", "unknown")
                    layer_counts[layer] += 1
                    domain = item.get("event_domain", "unknown")
                    domain_counts[domain] += 1

                elif item.get("entry_type") == "session_stats":
                    total_session_reports += 1
                    for key in aggregate_stats:
                        val = item.get(key)
                        if val is not None:
                            aggregate_stats[key] += int(val)

            # Top 10 most blocked/warned domains
            top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            return {
                "total_events": total_events,
                "total_session_reports": total_session_reports,
                "by_event_type": dict(event_counts),
                "by_layer": dict(layer_counts),
                "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
                "aggregate_session_stats": aggregate_stats,
            }

    except Exception:
        logger.exception("Failed to read telemetry stats")
        raise HTTPException(status_code=500, detail="Failed to read stats")

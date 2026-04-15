"""Scheduled jobs — daily bloom filter generation and blacklist ingestion."""

import logging
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.bloom import generate_whitelist_bloom, generate_blacklist_bloom
from app.config import settings
from app.ingestion.runner import run_blacklist_ingestion

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

WHITELIST_FILENAME = "whitelist.bloom"
BLACKLIST_FILENAME = "blacklist.bloom"


def _bloom_dir() -> Path:
    """Return the bloom directory, creating it if needed."""
    p = Path(settings.bloom_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_bloom_file(name: str) -> bytes | None:
    """Read a bloom filter file from disk. Returns None if not found."""
    path = _bloom_dir() / name
    if path.exists():
        return path.read_bytes()
    return None


async def generate_and_store_bloom_filters() -> dict:
    """Generate both bloom filters and write them to disk.

    Returns stats about the generated filters.
    """
    bloom_dir = _bloom_dir()

    logger.info("Generating whitelist bloom filter...")
    wl_data = await generate_whitelist_bloom()
    wl_path = bloom_dir / WHITELIST_FILENAME
    wl_path.write_bytes(wl_data)
    logger.info(f"Whitelist bloom written to {wl_path} ({len(wl_data)} bytes)")

    logger.info("Generating blacklist bloom filter...")
    bl_data = await generate_blacklist_bloom()
    bl_path = bloom_dir / BLACKLIST_FILENAME
    bl_path.write_bytes(bl_data)
    logger.info(f"Blacklist bloom written to {bl_path} ({len(bl_data)} bytes)")

    return {
        "whitelist_bytes": len(wl_data),
        "blacklist_bytes": len(bl_data),
    }


async def _daily_job() -> None:
    """Combined daily job: ingest blacklists, then regenerate bloom filters."""
    logger.info("=== Daily scheduled job starting ===")

    # 1. Ingest public blacklist feeds
    try:
        stats = await run_blacklist_ingestion()
        logger.info(f"Blacklist ingestion complete: {stats}")
    except Exception:
        logger.exception("Blacklist ingestion failed")

    # 2. Regenerate bloom filters (even if ingestion failed — whitelist still valid)
    try:
        bloom_stats = await generate_and_store_bloom_filters()
        logger.info(f"Bloom filters regenerated: {bloom_stats}")
    except Exception:
        logger.exception("Bloom filter generation failed")

    logger.info("=== Daily scheduled job finished ===")


def start_scheduler() -> None:
    """Configure and start the APScheduler."""
    scheduler.add_job(
        _daily_job,
        trigger=CronTrigger(hour=3, minute=0, timezone="UTC"),
        id="daily_ingestion_and_bloom",
        name="Daily blacklist ingestion + bloom filter generation",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started — daily job at 03:00 UTC")


def stop_scheduler() -> None:
    """Shut down the scheduler gracefully."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")

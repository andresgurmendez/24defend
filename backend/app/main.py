import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.agent import load_whitelist_cache
from app.db import ensure_table
from app.scheduler import (
    generate_and_store_bloom_filters,
    start_scheduler,
    stop_scheduler,
)
from app.ingestion.runner import run_blacklist_ingestion
from app.routes.admin import router as admin_router
from app.routes.check import router as check_router

logger = logging.getLogger(__name__)


async def _startup_background_tasks():
    """Run ingestion + bloom generation in background so the server starts fast."""
    try:
        logger.warning("INGESTION START: fetching public threat feeds...")
        stats = await run_blacklist_ingestion()
        logger.warning(f"INGESTION DONE: {stats}")
    except Exception:
        logger.exception("INGESTION FAILED")

    try:
        logger.warning("BLOOM START: generating bloom filters...")
        result = await generate_and_store_bloom_filters()
        logger.warning(f"BLOOM DONE: {result}")
    except Exception:
        logger.exception("BLOOM FAILED")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_table()
    await load_whitelist_cache()

    # Start ingestion in background — don't block server startup
    asyncio.create_task(_startup_background_tasks())

    start_scheduler()

    yield

    stop_scheduler()


app = FastAPI(
    title="24Defend API",
    description="Domain threat intelligence API for the 24Defend iOS app",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(check_router)
app.include_router(admin_router)


@app.get("/health")
async def health():
    return {"status": "ok"}

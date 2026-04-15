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


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_table()
    await load_whitelist_cache()

    # Run initial ingestion + bloom generation on startup
    try:
        logger.info("Running startup blacklist ingestion...")
        await run_blacklist_ingestion()
    except Exception:
        logger.exception("Startup blacklist ingestion failed")

    try:
        logger.info("Running startup bloom filter generation...")
        await generate_and_store_bloom_filters()
    except Exception:
        logger.exception("Startup bloom filter generation failed")

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

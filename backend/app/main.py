import asyncio
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Configure Python logging so app-level logger.info/warning/error lines
# reach stdout (and therefore CloudWatch, via the Fargate log driver).
# Without this the root logger's default level is WARNING and app INFO
# messages get dropped — meaning we had zero visibility into per-request
# agent behavior (Starting LangGraph investigation, IP owner, etc.) even
# though the code emitted plenty of logs.
#
# `force=True` overrides any handler uvicorn set up before this import
# ran (uvicorn attaches its own root handlers when started).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
    force=True,
)

from app.agent import load_whitelist_cache
from app.config import settings
from app.db import ensure_table
from app.scheduler import (
    generate_and_store_bloom_filters,
    start_scheduler,
    stop_scheduler,
)
from app.ingestion.runner import run_blacklist_ingestion
from app.popular_domains import get_instance as get_popular_domains
from app.routes.admin import router as admin_router, public_router as admin_public_router
from app.routes.check import router as check_router
from app.routes.telemetry import router as telemetry_router

logger = logging.getLogger(__name__)


async def _load_popular_domains():
    """Fetch Majestic top 100K into the pre-agent short-circuit set.

    Runs on startup and does not block the server — until it finishes, is_popular()
    falls back to the curated vendor list (still catches ~50 well-known infra roots).
    """
    try:
        logger.warning("POPULAR START: fetching Majestic top 100K...")
        total = await get_popular_domains().load_majestic()
        logger.warning(f"POPULAR DONE: {total} popular domains loaded")
    except Exception:
        logger.exception("POPULAR FAILED (short-circuit will use vendor list only)")


async def _startup_background_tasks():
    """Run ingestion + bloom generation in background so the server starts fast."""
    await _load_popular_domains()

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

# Only GET (read-only, public endpoints consumed by the internal dashboard
# SPA). Never widen this to allow credentials/mutations without auth in front.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.dashboard_cors_origins.split(",") if o.strip()],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(check_router)
app.include_router(admin_router)
app.include_router(admin_public_router)
app.include_router(telemetry_router)


@app.get("/health")
async def health():
    return {"status": "ok"}

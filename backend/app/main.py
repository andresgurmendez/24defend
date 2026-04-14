from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import ensure_table
from app.routes.admin import router as admin_router
from app.routes.check import router as check_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_table()
    yield


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

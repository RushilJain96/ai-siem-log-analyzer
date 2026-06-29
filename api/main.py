"""FastAPI application entry point.

Wires startup/shutdown lifecycle, configures logging, registers route
modules. Should stay thin — application setup only. Business logic
belongs in api/routes/, db/crud.py, and model/.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from api.routes import logs, stats
from core.config import settings
from core.logging import configure_logging
from db.database import SessionLocal, init_db

# Configure logging BEFORE creating the FastAPI app. Uvicorn's own
# loggers come up during app instantiation; if we configure logging
# after that, startup messages from uvicorn are emitted with the
# default plain-text formatter.
configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown lifecycle hooks.

    Runs init_db() once at startup. Anything we needed to clean up
    on shutdown would go after the yield.
    """
    logger.info(
        "Application starting",
        extra={"app_name": settings.app_name, "env": settings.app_env},
    )
    init_db()
    yield
    logger.info("Application shutting down")


app = FastAPI(
    title="AI-Driven SIEM Log Analyzer",
    description="Ingests network logs, detects anomalies via Isolation Forest, "
    "and surfaces high-risk alerts through a REST API and dashboard.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(logs.router)
app.include_router(stats.router)


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    """Point clients at the auto-generated API documentation."""
    return {"name": settings.app_name, "docs": "/docs"}


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Readiness probe: confirm the API process is up AND the database is reachable.

    Returns 200 only if a trivial SELECT 1 against the database succeeds.
    If the database is down, returns 503 via raised exception.
    """
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    finally:
        db.close()
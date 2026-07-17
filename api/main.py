"""FastAPI application entry point.

Wires startup/shutdown lifecycle, configures logging, registers route
modules. Should stay thin — application setup only. Business logic
belongs in api/routes/, db/crud.py, and model/.
"""
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from api.realtime import manager
from api.routes import dashboard, logs, stats
from core.config import settings
from core.logging import configure_logging
from db.database import SessionLocal, init_db
from model.inference import AnomalyScorer

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"

# Configure logging BEFORE creating the FastAPI app. Uvicorn's own
# loggers come up during app instantiation; if we configure logging
# after that, startup messages from uvicorn are emitted with the
# default plain-text formatter.
configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown lifecycle hooks.

    Runs init_db() once at startup, and tries to load the fitted
    anomaly detector once here too -- loading pickled sklearn objects
    per-request would be slow and wasteful, so it happens exactly once
    and is stored on app.state for routes to read via Depends(get_scorer).

    model/preprocessor.pkl and model/isolation_forest.pkl are gitignored
    (each developer/CI-run regenerates them locally by running
    scripts/fit_pipeline.py and scripts/train_detector.py against a real
    CICIDS download) -- a fresh clone or CI won't have them. That's not
    a startup failure: the API still serves ingest/list/stats, it just
    can't score anomalies until those artifacts exist. app.state.scorer
    stays None in that case, and /logs/ingest leaves is_alert/
    anomaly_score at their defaults for every entry.

    Anything we needed to clean up on shutdown would go after the yield.
    """
    logger.info(
        "Application starting",
        extra={"app_name": settings.app_name, "env": settings.app_env},
    )
    init_db()

    # Capture the running event loop so the SYNC /logs/ingest route (run
    # in a worker thread) can schedule WebSocket broadcasts onto it. See
    # api/realtime.py for why this bridge is needed.
    manager.bind_loop(asyncio.get_running_loop())

    try:
        app.state.scorer = AnomalyScorer.load_default()
        logger.info("Anomaly detector loaded; /logs/ingest will score entries")
    except FileNotFoundError:
        app.state.scorer = None
        logger.warning(
            "No trained model found (model/preprocessor.pkl / "
            "model/isolation_forest.pkl missing) -- /logs/ingest will "
            "accept logs but skip anomaly detection. Run "
            "scripts/fit_pipeline.py and scripts/train_detector.py to "
            "enable it."
        )

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
app.include_router(dashboard.router)

# Serve the live dashboard as static files at /dashboard (html=True makes
# /dashboard/ serve index.html). The dashboard is a self-contained
# HTML/CSS/JS bundle — no build step, no framework — that connects to the
# /ws WebSocket for the real-time feed.
if DASHBOARD_DIR.exists():
    app.mount(
        "/dashboard",
        StaticFiles(directory=DASHBOARD_DIR, html=True),
        name="dashboard",
    )


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    """Point clients at the docs and the live dashboard."""
    return {"name": settings.app_name, "docs": "/docs", "dashboard": "/dashboard"}


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
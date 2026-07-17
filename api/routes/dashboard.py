"""WebSocket endpoint for the live SOC dashboard (Day 9).

The dashboard opens one long-lived WebSocket here and receives EVERY
ingested log — not just alerts — as it's scored and stored (see
api/routes/logs.py's ingest broadcast). Each frame is a JSON object of
the shape {"type": "log", "data": {...LogResponse, "top_features": [...]}}.
Emitting all logs (benign included) lets the live stream show normal
traffic too; at production throughput you'd throttle or split channels.

This endpoint is push-only: we don't act on client messages, we just
hold the socket open and let ConnectionManager fan out broadcasts to it.
"""
import logging

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from api.realtime import manager
from api.routes.logs import get_scorer
from model.inference import AnomalyScorer

router = APIRouter(tags=["dashboard"])
logger = logging.getLogger(__name__)


@router.get("/model/info")
def model_info(scorer: AnomalyScorer | None = Depends(get_scorer)) -> dict:
    """Real detector metadata for the dashboard's Model Status panel.

    Reads the scorer through the get_scorer DEPENDENCY (not app.state
    directly) so tests can override it deterministically — otherwise the
    result depends on whether the machine happens to have trained .pkl
    files on disk, which is exactly how the first version of this
    endpoint's test flaked. Returns status='unavailable' when no model
    is loaded (graceful degradation), shown honestly in the panel.
    """
    if scorer is None:
        return {"status": "unavailable"}

    detector = scorer.detector
    return {
        "status": "loaded",
        "model_type": "Isolation Forest",
        "n_estimators": detector.model.n_estimators,
        "n_features": detector.n_features,
        "contamination": detector.contamination,
        "decision_threshold": round(detector.decision_threshold, 4),
        "live_connections": manager.connection_count,
    }


@router.websocket("/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    """Register the client, then block on receive until it disconnects.

    We never use the received text — awaiting receive_text() is simply
    how Starlette surfaces a client disconnect (it raises
    WebSocketDisconnect). Without a receive loop the server wouldn't
    notice the client going away and would keep a dead entry in the
    manager until the next failed broadcast.
    """
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:  # noqa: BLE001 — any error means this client is gone
        manager.disconnect(websocket)

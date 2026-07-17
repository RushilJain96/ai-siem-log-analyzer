"""Log-related API routes."""
from datetime import datetime
from enum import Enum

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.realtime import manager
from db.crud import create_log_entry, get_alerts, get_logs
from db.database import get_db
from db.models import LogEntry
from model.inference import AnomalyScorer
from model.severity import severity_for

router = APIRouter(prefix="/logs", tags=["logs"])


class Severity(str, Enum):
    """Alert severity tiers, accepted as a query param.

    A str Enum so FastAPI validates it automatically: an unknown value
    (?severity=banana) yields a 422 before any handler runs, rather
    than a silent empty result — consistent with the fail-loud stance
    from Day 5's LogIngest.
    """
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LogIngest(BaseModel):
    """Shape of an incoming log entry.

    All structured fields are optional except event_time — different log
    sources provide different subsets.

    is_alert and anomaly_score are NOT accepted from clients (Day 5) —
    accepting them was a Day 2 seed-data shortcut using CICIDS
    ground-truth labels to populate /stats before the detector existed.
    A caller asserting its own traffic is safe is a trust-boundary
    violation for an intrusion-detection API; only the server-side
    detector may set these now, via `features`.

    `features` holds whichever of the 18 flow-shape columns the caller
    can supply (see model.features.FEATURE_COLUMNS) — deliberately a
    dict, not 18 flat fields, so log sources that aren't CICIDS-flow
    shaped can still be ingested and stored, just without a score.
    Missing/omitted keys are imputed by the fitted pipeline, same as at
    training time (see model/inference.py).

    extra="forbid": a caller still sending is_alert/anomaly_score in the
    request body gets a loud 422, not a silently dropped field — for a
    field that used to gate security-relevant behavior, failing loud
    beats failing quiet.
    """
    model_config = {"extra": "forbid"}

    event_time: datetime
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    protocol: str | None = Field(default=None, max_length=32)
    event_type: str | None = Field(default=None, max_length=64)
    bytes_transferred: int | None = None
    duration_seconds: float | None = None
    flag: str | None = Field(default=None, max_length=16)
    raw_payload: str | None = None
    features: dict[str, float] | None = None


class LogResponse(BaseModel):
    """Shape returned for any GET on a log entry.

    `severity` is DERIVED from anomaly_score + is_alert at response time
    (see build_log_response), never stored — one source of truth for the
    tier cutoffs. Null for non-alerts.
    """
    id: int
    event_time: datetime
    created_at: datetime
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    event_type: str | None
    bytes_transferred: int | None
    duration_seconds: float | None
    flag: str | None
    anomaly_score: float | None
    is_alert: bool
    severity: str | None

    model_config = {"from_attributes": True}


def build_log_response(entry: LogEntry) -> LogResponse:
    """Build a LogResponse from an ORM row, computing severity.

    The ORM object has no `severity` attribute (it's not a column), so
    model_validate alone can't fill it — we compute it here from the
    stored anomaly_score + is_alert. Every place that returns a
    LogResponse goes through this, so the derivation happens in exactly
    one spot.
    """
    return LogResponse(
        **{field: getattr(entry, field) for field in LogResponse.model_fields
           if field != "severity"},
        severity=severity_for(entry.anomaly_score, entry.is_alert),
    )


def get_scorer(request: Request) -> AnomalyScorer | None:
    """Yield the AnomalyScorer loaded at startup (api/main.py's
    lifespan), or None if no trained model was available there.

    A FastAPI dependency, same pattern as get_db, so tests can override
    it the same way: app.dependency_overrides[get_scorer] = ...
    """
    return request.app.state.scorer


@router.post(
    "/ingest",
    response_model=LogResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_log(
    payload: LogIngest,
    db: Session = Depends(get_db),
    scorer: AnomalyScorer | None = Depends(get_scorer),
) -> LogResponse:
    """Accept a log entry, score it, persist it, return the stored row.

    Scoring only happens if BOTH a trained model is loaded AND the
    caller supplied `features` — either one missing means is_alert
    stays False and anomaly_score stays None. That's "detection
    unavailable for this entry," not an error: a log source that can't
    supply flow-shape stats should still be ingestable.
    """
    fields = payload.model_dump(exclude={"features"})
    top_features: list[dict] = []

    if scorer is not None and payload.features:
        result = scorer.score(payload.features)
        fields["is_alert"] = result["is_alert"]
        fields["anomaly_score"] = result["anomaly_score"]
        top_features = result["top_features"]
    else:
        fields["is_alert"] = False
        fields["anomaly_score"] = None

    entry = create_log_entry(db, **fields)
    response = build_log_response(entry)

    # Push this log to any connected dashboards. Fire-and-forget and a
    # no-op when nobody's watching, so it never affects the ingest
    # response. We broadcast every log (not just alerts) so the live
    # stream sees benign traffic too; at production throughput you'd
    # throttle or split channels, but at demo rates this is fine.
    _broadcast_log(response, top_features)

    return response


def _broadcast_log(response: LogResponse, top_features: list[dict]) -> None:
    """Fan a just-ingested log out to connected dashboard WebSockets.

    top_features (each feature's standardized deviation from the benign
    baseline — an interpretable PROXY, not the Isolation Forest's
    internal attribution; see AnomalyScorer.score) rides along so the
    dashboard's explanation panel can render without a second request.
    """
    message = {
        "type": "log",
        "data": {**response.model_dump(mode="json"), "top_features": top_features},
    }
    manager.broadcast_threadsafe(message)


@router.get("/alerts", response_model=list[LogResponse])
def list_alerts(
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list[LogResponse]:
    """Return flagged alerts, most-anomalous first.

    A convenience view for the single most common analyst action —
    "show me what fired" — ordered by anomaly_score descending so
    critical/high alerts sit at the top. Equivalent to
    `GET /logs?is_alert=true` but sorted for triage-by-urgency rather
    than recency.

    NOTE: registered before the "" route so "/logs/alerts" isn't
    swallowed as a path; FastAPI matches routes in declaration order.
    """
    rows = get_alerts(db, limit=limit)
    return [build_log_response(r) for r in rows]


@router.get("", response_model=list[LogResponse])
def list_logs(
    limit: int = 100,
    skip: int = 0,
    source_ip: str | None = None,
    is_alert: bool | None = None,
    severity: Severity | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    db: Session = Depends(get_db),
) -> list[LogResponse]:
    """Return stored logs, newest-ingested first, with optional filters.

    Filters (all optional, ANDed together): source_ip, is_alert,
    severity (low/medium/high/critical — an invalid value is rejected
    with 422 by the Severity enum), and a created_at window via
    start_time (inclusive) / end_time (exclusive).
    """
    # crud.get_logs handles filters and limit; skip is applied below
    # to keep the CRUD layer small. We trade slight inefficiency at
    # the route level for a thinner data layer.
    rows = get_logs(
        db,
        limit=limit + skip,
        source_ip=source_ip,
        is_alert=is_alert,
        severity=severity.value if severity is not None else None,
        start_time=start_time,
        end_time=end_time,
    )
    return [build_log_response(r) for r in rows[skip:]]
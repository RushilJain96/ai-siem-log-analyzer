"""Log-related API routes."""
from datetime import datetime

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.crud import create_log_entry, get_logs
from db.database import get_db
from model.inference import AnomalyScorer

router = APIRouter(prefix="/logs", tags=["logs"])


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
    """Shape returned for any GET on a log entry."""
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

    model_config = {"from_attributes": True}


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

    if scorer is not None and payload.features:
        result = scorer.score(payload.features)
        fields["is_alert"] = result["is_alert"]
        fields["anomaly_score"] = result["anomaly_score"]
    else:
        fields["is_alert"] = False
        fields["anomaly_score"] = None

    entry = create_log_entry(db, **fields)
    return LogResponse.model_validate(entry)


@router.get("", response_model=list[LogResponse])
def list_logs(
    limit: int = 100,
    skip: int = 0,
    source_ip: str | None = None,
    db: Session = Depends(get_db),
) -> list[LogResponse]:
    """Return stored logs, newest-ingested first.

    Supports pagination via limit/skip and optional filtering by
    source IP. Day 6 adds time-range and severity filters.
    """
    # crud.get_logs handles the filter and limit; skip is applied below
    # to keep the CRUD layer small. We trade slight inefficiency at
    # the route level for a thinner data layer.
    rows = get_logs(db, limit=limit + skip, source_ip=source_ip)
    return [LogResponse.model_validate(r) for r in rows[skip:]]
"""Log-related API routes."""
from datetime import datetime

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.crud import create_log_entry, get_logs
from db.database import get_db

router = APIRouter(prefix="/logs", tags=["logs"])


class LogIngest(BaseModel):
    """Shape of an incoming log entry.

    All structured fields are optional except event_time — different log
    sources provide different subsets. Day 1 stores whatever is sent;
    parsing and feature engineering (Day 2-3) will normalize across
    sources before insertion in later iterations.
    """
    event_time: datetime
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    protocol: str | None = Field(default=None, max_length=32)
    event_type: str | None = Field(default=None, max_length=64)
    bytes_transferred: int | None = None
    duration_seconds: float | None = None
    flag: str | None = Field(default=None, max_length=16)
    raw_payload: str | None = None


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


@router.post(
    "/ingest",
    response_model=LogResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_log(
    payload: LogIngest,
    db: Session = Depends(get_db),
) -> LogResponse:
    """Accept a log entry, persist it, return the stored row.

    Day 1: pure persistence. Day 5 wires this through the feature
    pipeline and Isolation Forest detector before returning, populating
    anomaly_score and is_alert.
    """
    entry = create_log_entry(db, **payload.model_dump())
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
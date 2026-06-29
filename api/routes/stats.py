"""Stats API routes."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.crud import get_stats
from db.database import get_db

router = APIRouter(prefix="/stats", tags=["stats"])


class StatsResponse(BaseModel):
    total_logs: int
    total_alerts: int
    alert_rate: float


@router.get("", response_model=StatsResponse)
def read_stats(db: Session = Depends(get_db)) -> StatsResponse:
    """Return summary metrics for the SIEM dashboard."""
    return StatsResponse(**get_stats(db))

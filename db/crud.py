"""Database read/write operations.

Thin layer between API routes and ORM models. Routes call these
functions; functions take a Session and return ORM objects or
primitive types. Keeps SQL knowledge concentrated in one module.
"""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import LogEntry


def create_log_entry(db: Session, **fields) -> LogEntry:
    """Insert a new log entry and return it with its assigned id.

    Caller passes the structured fields as keyword arguments matching
    LogEntry columns. The database auto-fills id and created_at.
    """
    entry = LogEntry(**fields)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_logs(
    db: Session,
    limit: int = 100,
    source_ip: str | None = None,
) -> list[LogEntry]:
    """Return recent log entries, optionally filtered by source IP.

    Ordered by ingestion time (created_at) descending — newest first.
    Uses created_at rather than event_time so late-arriving logs don't
    appear above more recently ingested ones.
    """
    stmt = select(LogEntry).order_by(LogEntry.created_at.desc()).limit(limit)
    if source_ip is not None:
        stmt = stmt.where(LogEntry.source_ip == source_ip)
    return list(db.scalars(stmt).all())


def get_alerts(db: Session, limit: int = 100) -> list[LogEntry]:
    """Return entries that the detector flagged as anomalous."""
    stmt = (
        select(LogEntry)
        .where(LogEntry.is_alert.is_(True))
        .order_by(LogEntry.created_at.desc())
        .limit(limit)
    )
    return list(db.scalars(stmt).all())


def get_stats(db: Session) -> dict[str, int | float]:
    """Return summary counts for the /stats endpoint."""
    total_logs = db.scalar(select(func.count()).select_from(LogEntry)) or 0
    total_alerts = db.scalar(
        select(func.count()).select_from(LogEntry).where(LogEntry.is_alert.is_(True))
    ) or 0

    alert_rate = round(total_alerts / total_logs, 4) if total_logs else 0.0

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "alert_rate": alert_rate,
    }
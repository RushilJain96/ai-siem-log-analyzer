"""Database read/write operations.

Thin layer between API routes and ORM models. Routes call these
functions; functions take a Session and return ORM objects or
primitive types. Keeps SQL knowledge concentrated in one module.
"""
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import LogEntry
from model.severity import SEVERITIES, score_bounds_for


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
    is_alert: bool | None = None,
    severity: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[LogEntry]:
    """Return recent log entries, newest-ingested first, with optional filters.

    Ordered by ingestion time (created_at) descending. Uses created_at
    rather than event_time so late-arriving logs don't appear above more
    recently ingested ones.

    Filters compose (all provided ones are ANDed together):
    - source_ip: exact match
    - is_alert: True/False
    - severity: one of model.severity.SEVERITIES. Translated to an
      indexable anomaly_score range (via score_bounds_for) rather than
      computed per-row -- and implies is_alert=True, since only alerts
      have a severity (a benign row with a score in the "high" range is
      still not a "high" alert). The caller is responsible for passing a
      valid tier; an unknown one raises ValueError.
    - start_time / end_time: inclusive lower / exclusive upper bound on
      created_at.
    """
    stmt = select(LogEntry).order_by(LogEntry.created_at.desc()).limit(limit)

    if source_ip is not None:
        stmt = stmt.where(LogEntry.source_ip == source_ip)
    if is_alert is not None:
        stmt = stmt.where(LogEntry.is_alert.is_(is_alert))
    if severity is not None:
        if severity not in SEVERITIES:
            raise ValueError(
                f"Unknown severity {severity!r}; expected one of {SEVERITIES}."
            )
        lower, upper = score_bounds_for(severity)
        # severity is only meaningful for alerts; a non-alert row whose
        # score happens to land in this range is NOT this severity.
        stmt = stmt.where(
            LogEntry.is_alert.is_(True),
            LogEntry.anomaly_score >= lower,
            LogEntry.anomaly_score < upper,
        )
    if start_time is not None:
        stmt = stmt.where(LogEntry.created_at >= start_time)
    if end_time is not None:
        stmt = stmt.where(LogEntry.created_at < end_time)

    return list(db.scalars(stmt).all())


def get_alerts(db: Session, limit: int = 100) -> list[LogEntry]:
    """Return flagged entries, most-anomalous first.

    Ordered by anomaly_score descending (NOT created_at) so the highest-
    severity alerts surface at the top -- an alerts view exists for
    triage-by-urgency, not triage-by-recency. Entries with a null score
    (flagged before a model was available, if that ever happens) sort
    last under SQL's NULLS-LAST-on-DESC behavior in SQLite.
    """
    stmt = (
        select(LogEntry)
        .where(LogEntry.is_alert.is_(True))
        .order_by(LogEntry.anomaly_score.desc())
        .limit(limit)
    )
    return list(db.scalars(stmt).all())


def get_stats(db: Session) -> dict:
    """Return summary counts for the /stats endpoint.

    Includes a per-severity breakdown of alerts. The breakdown is
    computed from anomaly_score ranges (the same bounds severity_for
    uses), so it always agrees with the severity each individual log
    reports -- one source of truth for the cutoffs.
    """
    total_logs = db.scalar(select(func.count()).select_from(LogEntry)) or 0
    total_alerts = db.scalar(
        select(func.count()).select_from(LogEntry).where(LogEntry.is_alert.is_(True))
    ) or 0

    alert_rate = round(total_alerts / total_logs, 4) if total_logs else 0.0

    by_severity = {}
    for tier in SEVERITIES:
        lower, upper = score_bounds_for(tier)
        count = db.scalar(
            select(func.count())
            .select_from(LogEntry)
            .where(
                LogEntry.is_alert.is_(True),
                LogEntry.anomaly_score >= lower,
                LogEntry.anomaly_score < upper,
            )
        ) or 0
        by_severity[tier] = count

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "alert_rate": alert_rate,
        "alerts_by_severity": by_severity,
    }
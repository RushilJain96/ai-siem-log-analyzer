"""SQLAlchemy table definitions."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


def _utcnow() -> datetime:
    """Module-level helper so column defaults can reference it.

    Used instead of inlining `lambda: datetime.now(timezone.utc)` at
    each column to keep schema declarations readable.
    """
    return datetime.now(timezone.utc)


class LogEntry(Base):
    """One ingested network log row.

    Stores both the parsed structured fields (queryable) and the raw
    payload (forensic). Anomaly metadata (anomaly_score, is_alert) is
    populated by the detection pipeline after ingestion.
    """

    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # When the log event occurred (from the log payload itself).
    # Distinct from created_at, which is when we ingested it.
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )

    # When our system stored this row. Used for "logs ingested in last
    # hour" style queries where we don't want late-arriving logs to
    # confuse the picture.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    # 45 chars covers IPv6 in its longest representation
    # (ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255).
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Numerical features the Isolation Forest will consume on Day 4.
    # All nullable because not every log source provides every field.
    bytes_transferred: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    flag: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Forensic record of the original log. Not queried — for replay
    # and audit only. Text rather than JSONB so we stay portable
    # between SQLite (dev) and Postgres (prod).
    raw_payload: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Anomaly detection output. Both null until the detector runs.
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_alert: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
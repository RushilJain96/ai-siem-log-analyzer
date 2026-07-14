"""Database connection and session management.

This module owns the SQLAlchemy engine, session factory, and Base
class that all ORM models inherit from. It reads its configuration
exclusively from core.config — never from os.environ directly.
"""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from core.config import settings


# SQLite needs check_same_thread=False because FastAPI runs requests in a
# thread pool. Postgres doesn't (it has real connection pooling). Compute
# the check once and reuse it, rather than testing the URL twice.
is_sqlite = settings.database_url.startswith("sqlite")

# pool_pre_ping issues a lightweight liveness check before handing out a
# pooled connection, transparently replacing dead ones. It's a networked-
# DB concern (Postgres, Day 8): a connection can go stale if the DB
# restarts or idles out, and without this the app raises "server closed
# the connection unexpectedly" on the next query instead of reconnecting.
# SQLite is a local file — connections don't go stale — so we skip it there.
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if is_sqlite else {},
    pool_pre_ping=not is_sqlite,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base class for all ORM models.

    All table classes (LogEntry, etc.) inherit from this. SQLAlchemy
    uses the MRO to find this class and register the tables it sees.
    """
    pass


def init_db() -> None:
    """Create all tables defined on Base.metadata.

    Idempotent — safe to call on every application startup. Generates
    CREATE TABLE IF NOT EXISTS for each table. Does NOT modify existing
    tables; for schema changes in production we'd use Alembic.

    Must be called AFTER all model modules have been imported, so that
    Base.metadata knows about every table. Called from api/main.py's
    startup lifespan.
    """
    # Import models so their Base subclasses register with Base.metadata.
    # Without this import, Base.metadata is empty and create_all does nothing.
    from db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Yield one database session per request, then close it.

    Used as a FastAPI dependency via Depends(get_db). FastAPI advances
    the generator to yield, passes the session to the route, and runs
    the finally block after the response is sent — guaranteeing close
    even on exceptions.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

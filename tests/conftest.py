"""Shared pytest fixtures for the test suite.

Files named conftest.py are automatically discovered by pytest — every
test in the same directory (or subdirectory) gets access to the fixtures
defined here without any explicit import. This is pytest's mechanism
for sharing setup code.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.main import app
from db.database import Base, get_db


@pytest.fixture
def client():
    """Yield a FastAPI TestClient backed by a fresh in-memory SQLite database.

    Each test that requests this fixture gets a clean database — no
    state leaks between tests, no ordering dependencies.

    The override of get_db ensures the application uses the in-memory
    engine instead of the real siem.db file.
    """
    # poolclass=StaticPool keeps a single connection alive for the
    # whole test. Without it, every CRUD call gets a fresh connection
    # to a fresh in-memory database — which means tables created in
    # one connection are invisible to the next.
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Create the schema in the test database.
    from db import models  # noqa: F401 — side-effect import registers tables
    Base.metadata.create_all(bind=test_engine)

    # Override the get_db dependency so route handlers use the test session.
    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c

    # Clean up the override so it doesn't leak into the next test.
    app.dependency_overrides.clear()
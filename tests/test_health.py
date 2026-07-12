"""End-to-end tests for the Day 1 endpoints.

These tests exercise the full HTTP-to-database flow against an in-memory
SQLite engine. Each test receives a fresh client+database via the `client`
fixture defined in conftest.py.
"""


def test_health_returns_ok(client):
    """The /health endpoint should return 200 and a status payload."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_points_at_docs(client):
    """The / endpoint should expose the docs URL for discoverability."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["docs"] == "/docs"


def test_ingest_creates_log(client):
    """POST /logs/ingest should return 201 and the stored row."""
    payload = {
        "event_time": "2026-06-29T17:00:00+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "protocol": "TCP",
        "event_type": "connection",
        "bytes_transferred": 1024,
        "duration_seconds": 0.5,
        "flag": "ACK",
    }
    response = client.post("/logs/ingest", json=payload)

    assert response.status_code == 201
    body = response.json()
    assert body["id"] >= 1
    assert body["source_ip"] == "10.0.0.1"
    assert body["bytes_transferred"] == 1024
    assert body["is_alert"] is False
    assert body["anomaly_score"] is None


def test_list_logs_includes_ingested(client):
    """GET /logs should return logs we just ingested."""
    payload = {
        "event_time": "2026-06-29T17:00:00+00:00",
        "source_ip": "10.0.0.5",
        "protocol": "UDP",
    }
    client.post("/logs/ingest", json=payload)

    response = client.get("/logs")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "10.0.0.5"
    assert rows[0]["protocol"] == "UDP"


def test_stats_reflects_ingested_logs(client):
    """GET /stats should count ingested logs accurately."""
    # Empty database to start
    response = client.get("/stats")
    assert response.json() == {
        "total_logs": 0,
        "total_alerts": 0,
        "alert_rate": 0.0,
        "alerts_by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    }

    # Ingest two logs
    for ip in ["10.0.0.1", "10.0.0.2"]:
        client.post("/logs/ingest", json={
            "event_time": "2026-06-29T17:00:00+00:00",
            "source_ip": ip,
        })

    # Stats should reflect the new count
    response = client.get("/stats")
    body = response.json()
    assert body["total_logs"] == 2
    assert body["total_alerts"] == 0
    assert body["alert_rate"] == 0.0
    assert body["alerts_by_severity"] == {"low": 0, "medium": 0, "high": 0, "critical": 0}


def test_ingest_validates_event_time_required(client):
    """POST /logs/ingest without event_time should return 422 (validation error)."""
    payload = {"source_ip": "10.0.0.1"}  # missing required event_time
    response = client.post("/logs/ingest", json=payload)
    assert response.status_code == 422
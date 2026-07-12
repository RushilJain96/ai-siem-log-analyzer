"""End-to-end tests for Day 6: severity, alert view, and log filters.

Injects a synthetic AnomalyScorer (same override pattern as
test_ingest_detection.py) so ingested rows get real scores, then
exercises the new query surface: severity in responses, GET /logs
filters, GET /logs/alerts ordering, and the /stats breakdown.
"""
import numpy as np
import pandas as pd
import pytest

from api.main import app
from api.routes import logs as logs_route
from model.detector import Detector
from model.features import FEATURE_COLUMNS, FeaturePipeline
from model.inference import AnomalyScorer


def _make_benign_df(n_rows: int = 500) -> pd.DataFrame:
    rng = np.random.default_rng(seed=42)
    data = {name: rng.normal(0.0, 1.0, size=n_rows) for name in FEATURE_COLUMNS}
    return pd.DataFrame(data)


def _fitted_scorer() -> AnomalyScorer:
    df = _make_benign_df()
    pipeline = FeaturePipeline().fit(df)
    detector = Detector().fit(pipeline.transform(df))
    detector.set_decision_threshold(0.01)
    return AnomalyScorer(pipeline, detector)


@pytest.fixture
def scored_client(client):
    app.dependency_overrides[logs_route.get_scorer] = _fitted_scorer
    yield client


def _ingest(client, *, features=None, **extra):
    payload = {"event_time": "2026-06-29T17:00:00+00:00"}
    payload.update(extra)
    if features is not None:
        payload["features"] = features
    return client.post("/logs/ingest", json=payload)


def _normal_features():
    return {col: 0.0 for col in FEATURE_COLUMNS}


def _far_outlier_features():
    return {col: 40.0 for col in FEATURE_COLUMNS}


# --- severity appears in responses --------------------------------------


def test_non_alert_has_null_severity(scored_client):
    body = _ingest(scored_client, features=_normal_features()).json()
    assert body["is_alert"] is False
    assert body["severity"] is None


def test_alert_has_a_severity(scored_client):
    body = _ingest(scored_client, features=_far_outlier_features()).json()
    assert body["is_alert"] is True
    assert body["severity"] in {"low", "medium", "high", "critical"}


def test_far_outlier_is_critical(scored_client):
    """A wildly out-of-distribution row should score near 1.0 → critical."""
    body = _ingest(scored_client, features=_far_outlier_features()).json()
    assert body["anomaly_score"] > 0.75
    assert body["severity"] == "critical"


def test_ingest_without_features_has_null_severity(scored_client):
    body = _ingest(scored_client).json()
    assert body["severity"] is None


# --- GET /logs filters ---------------------------------------------------


def test_is_alert_filter_returns_only_alerts(scored_client):
    _ingest(scored_client, features=_normal_features())
    _ingest(scored_client, features=_far_outlier_features())

    rows = scored_client.get("/logs?is_alert=true").json()
    assert len(rows) == 1
    assert rows[0]["is_alert"] is True


def test_is_alert_false_filter_returns_only_non_alerts(scored_client):
    _ingest(scored_client, features=_normal_features())
    _ingest(scored_client, features=_far_outlier_features())

    rows = scored_client.get("/logs?is_alert=false").json()
    assert len(rows) == 1
    assert rows[0]["is_alert"] is False


def test_severity_filter_returns_matching_tier(scored_client):
    _ingest(scored_client, features=_normal_features())       # non-alert
    _ingest(scored_client, features=_far_outlier_features())  # critical

    rows = scored_client.get("/logs?severity=critical").json()
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"


def test_severity_filter_empty_when_no_match(scored_client):
    _ingest(scored_client, features=_far_outlier_features())  # critical only
    rows = scored_client.get("/logs?severity=low").json()
    assert rows == []


def test_invalid_severity_is_422(scored_client):
    response = scored_client.get("/logs?severity=banana")
    assert response.status_code == 422


# --- GET /logs/alerts ----------------------------------------------------


def test_alerts_endpoint_excludes_non_alerts(scored_client):
    _ingest(scored_client, features=_normal_features())
    _ingest(scored_client, features=_far_outlier_features())

    rows = scored_client.get("/logs/alerts").json()
    assert len(rows) == 1
    assert rows[0]["is_alert"] is True


def test_alerts_endpoint_orders_by_score_descending(scored_client):
    """Most-anomalous first — the whole point of an alerts view."""
    # A mid-range alert (features shifted a little) and a far outlier.
    mild = {col: 3.0 for col in FEATURE_COLUMNS}
    _ingest(scored_client, features=mild)
    _ingest(scored_client, features=_far_outlier_features())

    rows = scored_client.get("/logs/alerts").json()
    assert len(rows) >= 2
    scores = [r["anomaly_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)


# --- /stats breakdown ----------------------------------------------------


def test_stats_severity_breakdown_counts_critical(scored_client):
    _ingest(scored_client, features=_normal_features())       # non-alert
    _ingest(scored_client, features=_far_outlier_features())  # critical

    stats = scored_client.get("/stats").json()
    assert stats["total_alerts"] == 1
    assert stats["alerts_by_severity"]["critical"] == 1
    assert stats["alerts_by_severity"]["low"] == 0


def test_stats_breakdown_sums_to_total_alerts(scored_client):
    for _ in range(3):
        _ingest(scored_client, features=_far_outlier_features())
    _ingest(scored_client, features=_normal_features())

    stats = scored_client.get("/stats").json()
    assert sum(stats["alerts_by_severity"].values()) == stats["total_alerts"]
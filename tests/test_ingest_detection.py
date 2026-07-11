"""End-to-end tests for Day 5's detection wiring on POST /logs/ingest.

Exercises the full HTTP -> scoring -> database flow. Where a working
detector is needed, AnomalyScorer is injected via dependency override
-- the same mechanism conftest.py uses for get_db -- with a synthetic,
in-memory fitted scorer. No real .pkl files are touched anywhere here.
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
    data = {
        name: rng.normal(loc=0.0, scale=1.0, size=n_rows) for name in FEATURE_COLUMNS
    }
    return pd.DataFrame(data)


def _fitted_scorer() -> AnomalyScorer:
    df = _make_benign_df()
    pipeline = FeaturePipeline().fit(df)
    detector = Detector().fit(pipeline.transform(df))
    detector.set_decision_threshold(0.01)
    return AnomalyScorer(pipeline, detector)


@pytest.fixture
def scored_client(client):
    """The standard `client` fixture with a real (synthetic, in-memory)
    AnomalyScorer injected -- exercises the scored path without needing
    real .pkl files on disk. conftest's `client` fixture already clears
    app.dependency_overrides on teardown, so no cleanup needed here."""
    app.dependency_overrides[logs_route.get_scorer] = _fitted_scorer
    yield client

@pytest.fixture
def unscored_client(client):
    """The standard `client` fixture with AnomalyScorer explicitly
    forced to None -- makes "no model loaded" deterministic regardless
    of whether this particular machine happens to have real .pkl files
    sitting on disk locally from an earlier training run (CI never
    does, but a dev machine often does, as this test just proved)."""
    app.dependency_overrides[logs_route.get_scorer] = lambda: None
    yield client


def _base_payload(**overrides) -> dict:
    payload = {"event_time": "2026-06-29T17:00:00+00:00", "source_ip": "10.0.0.1"}
    payload.update(overrides)
    return payload


# --- is_alert/anomaly_score can no longer be set by the client -----------


def test_ingest_rejects_client_supplied_is_alert(client):
    response = client.post("/logs/ingest", json=_base_payload(is_alert=True))
    assert response.status_code == 422


def test_ingest_rejects_client_supplied_anomaly_score(client):
    response = client.post("/logs/ingest", json=_base_payload(anomaly_score=0.9))
    assert response.status_code == 422


# --- no trained model loaded (the default test-env state) ----------------


def test_ingest_without_features_leaves_defaults(client):
    response = client.post("/logs/ingest", json=_base_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["is_alert"] is False
    assert body["anomaly_score"] is None


def test_ingest_with_features_but_no_loaded_scorer_still_ingests(unscored_client):
    """features are accepted and stored-alongside even when no model is
    available -- detection is unavailable, that's not a request error."""
    features = {col: 0.0 for col in FEATURE_COLUMNS}
    response = unscored_client.post("/logs/ingest", json=_base_payload(features=features))
    assert response.status_code == 201
    body = response.json()
    assert body["is_alert"] is False
    assert body["anomaly_score"] is None


# --- a scorer is loaded ----------------------------------------------------


def test_ingest_flags_far_outlier_features_when_scorer_present(scored_client):
    features = {col: 40.0 for col in FEATURE_COLUMNS}
    response = scored_client.post("/logs/ingest", json=_base_payload(features=features))
    assert response.status_code == 201
    body = response.json()
    assert body["is_alert"] is True
    assert body["anomaly_score"] > 0.5


def test_ingest_does_not_flag_typical_features_when_scorer_present(scored_client):
    features = {col: 0.0 for col in FEATURE_COLUMNS}
    response = scored_client.post("/logs/ingest", json=_base_payload(features=features))
    assert response.status_code == 201
    body = response.json()
    assert body["is_alert"] is False


def test_ingest_with_scorer_but_no_features_still_leaves_defaults(scored_client):
    """A scorer being available doesn't force scoring -- an entry with
    no features simply has nothing to score."""
    response = scored_client.post("/logs/ingest", json=_base_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["is_alert"] is False
    assert body["anomaly_score"] is None


def test_ingest_scores_with_partial_features(scored_client):
    """A subset of the 18 columns should still produce a real score via
    the pipeline's median imputation, not an error."""
    partial = {"Flow Duration": 0.0, "SYN Flag Count": 0.0}
    response = scored_client.post("/logs/ingest", json=_base_payload(features=partial))
    assert response.status_code == 201
    assert response.json()["anomaly_score"] is not None


def test_ingested_score_persists_and_is_retrievable(scored_client):
    """The computed score isn't just returned once -- it's stored, and
    GET /logs reflects the same values POST returned."""
    features = {col: 40.0 for col in FEATURE_COLUMNS}
    post_response = scored_client.post(
        "/logs/ingest", json=_base_payload(features=features)
    )
    assert post_response.json()["is_alert"] is True

    list_response = scored_client.get("/logs")
    rows = list_response.json()
    assert len(rows) == 1
    assert rows[0]["is_alert"] is True
    assert rows[0]["anomaly_score"] == post_response.json()["anomaly_score"]
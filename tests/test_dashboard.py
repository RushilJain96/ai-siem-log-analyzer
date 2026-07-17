"""Tests for the dashboard-supporting HTTP surface (Day 9).

The WebSocket real-time path is covered by test_websocket.py (manager
unit tests) plus manual live verification. Here we lock the plain HTTP
bits the dashboard depends on: the model-info endpoint, the root link,
and that the static dashboard bundle is actually served.

model-info is tested through the get_scorer dependency override (both
branches), NOT by relying on whether this machine happens to have
trained .pkl files on disk — that ambient dependency is exactly what
made the first version of this test flake.
"""
import numpy as np
import pandas as pd

from api.main import app
from api.routes.logs import get_scorer
from model.detector import Detector
from model.features import FEATURE_COLUMNS, FeaturePipeline
from model.inference import AnomalyScorer


def _fitted_scorer() -> AnomalyScorer:
    rng = np.random.default_rng(seed=42)
    df = pd.DataFrame({c: rng.normal(0, 1, size=400) for c in FEATURE_COLUMNS})
    pipeline = FeaturePipeline().fit(df)
    detector = Detector().fit(pipeline.transform(df))
    return AnomalyScorer(pipeline, detector)


def test_root_links_to_dashboard(client):
    body = client.get("/").json()
    assert body["dashboard"] == "/dashboard"


def test_model_info_unavailable_when_no_model(client):
    """Force the no-model state via the dependency; the endpoint should
    report it honestly rather than error."""
    app.dependency_overrides[get_scorer] = lambda: None
    body = client.get("/model/info").json()
    assert body["status"] == "unavailable"
    # conftest's client fixture clears overrides on teardown.


def test_model_info_reports_real_metadata_when_loaded(client):
    """With a scorer present, the panel gets real detector metadata."""
    app.dependency_overrides[get_scorer] = _fitted_scorer
    body = client.get("/model/info").json()
    assert body["status"] == "loaded"
    assert body["model_type"] == "Isolation Forest"
    assert body["n_features"] == len(FEATURE_COLUMNS)
    assert 0 < body["decision_threshold"] <= 1
    assert body["n_estimators"] > 0


def test_dashboard_index_is_served(client):
    resp = client.get("/dashboard/")
    assert resp.status_code == 200
    assert "ORION" in resp.text


def test_dashboard_static_assets_are_served(client):
    for asset in ("styles.css", "app.js"):
        resp = client.get(f"/dashboard/{asset}")
        assert resp.status_code == 200
        assert len(resp.text) > 0

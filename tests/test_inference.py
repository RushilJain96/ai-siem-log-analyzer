"""Unit tests for model/inference.py.

Synthetic data throughout, same convention as test_features.py and
test_detector.py. AnomalyScorer's score() logic is tested with
in-memory fitted objects (no files); load_default() is tested
separately with tmp_path since it's specifically about file I/O.
"""
import numpy as np
import pandas as pd
import pytest

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
    X_train = pipeline.transform(df)
    detector = Detector().fit(X_train, feature_names=pipeline.feature_columns)
    detector.set_decision_threshold(0.01)
    return AnomalyScorer(pipeline, detector)


def _normal_features() -> dict[str, float]:
    """A feature dict that looks like the benign training distribution."""
    return {col: 0.0 for col in FEATURE_COLUMNS}


def _far_outlier_features() -> dict[str, float]:
    """A feature dict displaced far from the benign training distribution."""
    return {col: 40.0 for col in FEATURE_COLUMNS}


# --- score() -------------------------------------------------------------


def test_score_returns_expected_keys():
    scorer = _fitted_scorer()
    result = scorer.score(_normal_features())
    assert set(result.keys()) == {"is_alert", "anomaly_score"}


def test_score_types_are_json_safe():
    scorer = _fitted_scorer()
    result = scorer.score(_normal_features())
    assert isinstance(result["is_alert"], bool)
    assert isinstance(result["anomaly_score"], float)


def test_score_flags_far_outlier():
    scorer = _fitted_scorer()
    result = scorer.score(_far_outlier_features())
    assert result["is_alert"] is True


def test_score_does_not_flag_typical_row():
    scorer = _fitted_scorer()
    result = scorer.score(_normal_features())
    assert result["is_alert"] is False


def test_score_far_outlier_has_higher_anomaly_score_than_normal():
    scorer = _fitted_scorer()
    normal = scorer.score(_normal_features())
    outlier = scorer.score(_far_outlier_features())
    assert outlier["anomaly_score"] > normal["anomaly_score"]


def test_score_handles_partial_features_dict():
    """Missing keys should be imputed, not raise -- a log source with
    incomplete flow stats still gets a best-effort score."""
    scorer = _fitted_scorer()
    partial = {"Flow Duration": 0.0, "SYN Flag Count": 0.0}
    result = scorer.score(partial)
    assert isinstance(result["anomaly_score"], float)
    assert not np.isnan(result["anomaly_score"])


def test_score_handles_completely_empty_features_dict():
    """All keys missing -> all imputed to fit-time medians -> should
    score like a typical (median) benign row, not crash or NaN."""
    scorer = _fitted_scorer()
    result = scorer.score({})
    assert isinstance(result["anomaly_score"], float)
    assert not np.isnan(result["anomaly_score"])


def test_score_ignores_unknown_extra_keys():
    """A features dict with keys outside FEATURE_COLUMNS shouldn't
    break scoring -- only the 18 expected columns are read."""
    scorer = _fitted_scorer()
    features = _normal_features()
    features["Some Unrelated Column"] = 999.0
    result = scorer.score(features)
    assert isinstance(result["anomaly_score"], float)


# --- load_default() -------------------------------------------------------


def test_load_default_raises_when_pipeline_missing(tmp_path):
    detector_path = tmp_path / "detector.pkl"
    df = _make_benign_df()
    pipeline = FeaturePipeline().fit(df)
    detector = Detector().fit(pipeline.transform(df))
    detector.save(detector_path)

    with pytest.raises(FileNotFoundError):
        AnomalyScorer.load_default(
            pipeline_path=tmp_path / "nonexistent_pipeline.pkl",
            detector_path=detector_path,
        )


def test_load_default_raises_when_detector_missing(tmp_path):
    pipeline_path = tmp_path / "pipeline.pkl"
    df = _make_benign_df()
    FeaturePipeline().fit(df).save(pipeline_path)

    with pytest.raises(FileNotFoundError):
        AnomalyScorer.load_default(
            pipeline_path=pipeline_path,
            detector_path=tmp_path / "nonexistent_detector.pkl",
        )


def test_load_default_succeeds_and_scores(tmp_path):
    pipeline_path = tmp_path / "pipeline.pkl"
    detector_path = tmp_path / "detector.pkl"

    df = _make_benign_df()
    pipeline = FeaturePipeline().fit(df)
    pipeline.save(pipeline_path)
    detector = Detector().fit(pipeline.transform(df))
    detector.save(detector_path)

    scorer = AnomalyScorer.load_default(
        pipeline_path=pipeline_path, detector_path=detector_path
    )
    result = scorer.score(_normal_features())
    assert set(result.keys()) == {"is_alert", "anomaly_score"}
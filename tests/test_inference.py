"""Unit tests for model/inference.py.

Synthetic data throughout, same convention as test_features.py and
test_detector.py. AnomalyScorer's score() logic is tested with
in-memory fitted objects (no files); load_default() is tested
separately with tmp_path since it's specifically about file I/O.
"""
import numpy as np
import pandas as pd
import pytest

from model.artifact_integrity import ModelArtifactIntegrityError, write_model_card
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
    assert set(result.keys()) == {"is_alert", "anomaly_score", "top_features"}


def test_top_features_shape_and_ordering():
    """top_features should be the N most-deviating features, sorted by
    absolute deviation descending — genuine attribution, not a stub."""
    scorer = _fitted_scorer()
    result = scorer.score(_far_outlier_features())
    top = result["top_features"]

    assert len(top) == scorer.TOP_FEATURE_COUNT
    assert all(set(item.keys()) == {"feature", "deviation"} for item in top)
    # every reported feature is a real model column
    assert all(item["feature"] in FEATURE_COLUMNS for item in top)
    # sorted by |deviation| descending
    abs_devs = [abs(item["deviation"]) for item in top]
    assert abs_devs == sorted(abs_devs, reverse=True)


def test_top_features_reflect_the_shifted_columns():
    """A row shifted far from benign should show large positive
    deviations — the scaled value IS the standard-deviation distance
    from the learned benign mean."""
    scorer = _fitted_scorer()
    result = scorer.score(_far_outlier_features())
    # the single most-deviating feature should be well outside normal
    assert abs(result["top_features"][0]["deviation"]) > 3.0


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


# --- load_default() integrity contract (Day 10) ---------------------------
# load_default() no longer just loads files: it enforces the model-card
# integrity policy (verify each artifact's SHA-256 against model_card.json
# BEFORE deserializing). These lock the decision table. The in-memory
# scorer tests above bypass all of this by construction.


def _write_verified_triplet(tmp_path):
    """Write a matching preprocessor + detector + card into tmp_path.

    Returns (pipeline_path, detector_path, card_path)."""
    pipeline_path = tmp_path / "preprocessor.pkl"
    detector_path = tmp_path / "isolation_forest.pkl"
    card_path = tmp_path / "model_card.json"
    df = _make_benign_df()
    pipeline = FeaturePipeline().fit(df)
    pipeline.save(pipeline_path)
    Detector().fit(pipeline.transform(df)).save(detector_path)
    write_model_card(
        card_path,
        artifacts={
            "preprocessor.pkl": pipeline_path,
            "isolation_forest.pkl": detector_path,
        },
        artifact_version="v0.0.0-test",
        training={"dataset": "synthetic"},
        evaluation={"metrics": {}},
    )
    return pipeline_path, detector_path, card_path


def test_load_default_succeeds_and_scores_when_verified(tmp_path):
    pipeline_path, detector_path, card_path = _write_verified_triplet(tmp_path)
    scorer = AnomalyScorer.load_default(
        pipeline_path=pipeline_path,
        detector_path=detector_path,
        card_path=card_path,
    )
    result = scorer.score(_normal_features())
    assert set(result.keys()) == {"is_alert", "anomaly_score", "top_features"}
    assert scorer.release_metadata["artifact_version"] == "v0.0.0-test"


def test_load_default_all_absent_raises_file_not_found(tmp_path):
    """Nothing present -> the graceful path (caller MAY run model-less).
    Distinct from an integrity failure, which is fatal."""
    with pytest.raises(FileNotFoundError):
        AnomalyScorer.load_default(
            pipeline_path=tmp_path / "none.pkl",
            detector_path=tmp_path / "none2.pkl",
            card_path=tmp_path / "none.json",
        )


def test_load_default_partial_artifacts_fail_closed(tmp_path):
    """A detector + card but no preprocessor is unverifiable -> integrity
    error, never a silent partial load."""
    _, detector_path, card_path = _write_verified_triplet(tmp_path)
    with pytest.raises(ModelArtifactIntegrityError):
        AnomalyScorer.load_default(
            pipeline_path=tmp_path / "missing_preprocessor.pkl",
            detector_path=detector_path,
            card_path=card_path,
        )


def test_load_default_tampered_artifact_fails_closed(tmp_path):
    """A one-byte change to a verified artifact -> integrity error BEFORE
    it is ever unpickled."""
    pipeline_path, detector_path, card_path = _write_verified_triplet(tmp_path)
    corrupted = bytearray(detector_path.read_bytes())
    corrupted[50] ^= 0x01
    detector_path.write_bytes(corrupted)
    with pytest.raises(ModelArtifactIntegrityError):
        AnomalyScorer.load_default(
            pipeline_path=pipeline_path,
            detector_path=detector_path,
            card_path=card_path,
        )
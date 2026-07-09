"""Unit tests for model/detector.py.

Uses hand-crafted synthetic data throughout — never the real CICIDS
sample. Two data generators are used deliberately:

- _make_normal_matrix(): tight cluster around the origin, standing in
  for FeaturePipeline-scaled benign rows (mean~0, std~1 per feature,
  same shape fit() expects).
- _make_far_outliers(): rows displaced many standard deviations away,
  standing in for scaled attack rows that should score as anomalous.

evaluate() is tested separately from the model entirely, on hand-built
label arrays — it's a static method precisely so this is possible.
"""
import numpy as np
import pytest

from model.detector import Detector


def _make_normal_matrix(n_rows: int = 300, n_features: int = 6) -> np.ndarray:
    rng = np.random.default_rng(seed=42)
    return rng.normal(loc=0.0, scale=1.0, size=(n_rows, n_features))


def _make_far_outliers(n_rows: int = 20, n_features: int = 6) -> np.ndarray:
    rng = np.random.default_rng(seed=7)
    return rng.normal(loc=15.0, scale=1.0, size=(n_rows, n_features))


# --- fit() guardrails -------------------------------------------------


def test_fit_returns_self():
    detector = Detector()
    result = detector.fit(_make_normal_matrix())
    assert result is detector


def test_is_fitted_flag_starts_false():
    assert Detector().is_fitted is False


def test_is_fitted_flag_true_after_fit():
    detector = Detector().fit(_make_normal_matrix())
    assert detector.is_fitted is True


def test_fit_rejects_1d_input():
    detector = Detector()
    with pytest.raises(ValueError, match="2D"):
        detector.fit(np.ones(300))


def test_fit_rejects_too_few_rows():
    detector = Detector()
    with pytest.raises(ValueError, match="fewer than"):
        detector.fit(_make_normal_matrix(n_rows=50))


def test_fit_rejects_non_finite_values():
    X = _make_normal_matrix()
    X[0, 0] = np.inf
    detector = Detector()
    with pytest.raises(ValueError, match="inf/NaN"):
        detector.fit(X)


def test_fit_stores_n_features_and_feature_names():
    X = _make_normal_matrix(n_features=4)
    detector = Detector().fit(X, feature_names=["a", "b", "c", "d"])
    assert detector.n_features == 4
    assert detector.feature_names == ["a", "b", "c", "d"]


def test_fit_without_feature_names_leaves_none():
    detector = Detector().fit(_make_normal_matrix())
    assert detector.feature_names is None


def test_refitting_rebuilds_the_underlying_model():
    """Calling fit() twice should produce a genuinely new model, not
    reuse stale tree state — proven by checking identity changes."""
    detector = Detector()
    detector.fit(_make_normal_matrix())
    first_model = detector.model
    detector.fit(_make_normal_matrix())
    assert detector.model is not first_model


# --- calling methods before fit() --------------------------------------


def test_predict_before_fit_raises():
    with pytest.raises(RuntimeError, match="must be fit"):
        Detector().predict(_make_normal_matrix())


def test_anomaly_score_before_fit_raises():
    with pytest.raises(RuntimeError, match="must be fit"):
        Detector().anomaly_score(_make_normal_matrix())


def test_predict_with_score_before_fit_raises():
    with pytest.raises(RuntimeError, match="must be fit"):
        Detector().predict_with_score(_make_normal_matrix(n_rows=1))


def test_save_before_fit_raises(tmp_path):
    with pytest.raises(RuntimeError, match="must be fit"):
        Detector().save(tmp_path / "should_not_be_written.pkl")


def test_load_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        Detector.load(tmp_path / "nonexistent.pkl")


# --- feature-count validation at inference -----------------------------


def test_predict_rejects_wrong_feature_count():
    detector = Detector().fit(_make_normal_matrix(n_features=6))
    wrong_shape = _make_normal_matrix(n_rows=5, n_features=3)
    with pytest.raises(ValueError, match="features"):
        detector.predict(wrong_shape)


# --- predict() / anomaly_score() / classify() semantics -----------------


def test_predict_returns_only_zero_or_one():
    detector = Detector().fit(_make_normal_matrix())
    preds = detector.predict(_make_normal_matrix(n_rows=50))
    assert set(np.unique(preds)).issubset({0, 1})


def test_far_outliers_score_higher_than_normal_rows():
    """The core sanity check: rows far from the training distribution
    should get a materially higher anomaly_score than in-distribution
    rows. This is what makes the detector useful at all."""
    detector = Detector().fit(_make_normal_matrix())
    normal_scores = detector.anomaly_score(_make_normal_matrix(n_rows=50))
    outlier_scores = detector.anomaly_score(_make_far_outliers())
    assert outlier_scores.mean() > normal_scores.mean()


def test_anomaly_score_is_bounded_between_zero_and_one():
    detector = Detector().fit(_make_normal_matrix())
    X = np.vstack([_make_normal_matrix(n_rows=50), _make_far_outliers()])
    scores = detector.anomaly_score(X)
    assert (scores >= 0.0).all()
    assert (scores <= 1.0).all()


def test_classify_uses_decision_threshold_by_default():
    detector = Detector().fit(_make_normal_matrix())
    X = _make_far_outliers()
    scores = detector.anomaly_score(X)

    detector.set_decision_threshold(float(scores.min()))
    all_flagged = detector.classify(X)
    assert all_flagged.sum() == len(X)

    detector.set_decision_threshold(1.0)
    none_flagged = detector.classify(X)
    assert none_flagged.sum() == 0


def test_classify_explicit_threshold_overrides_decision_threshold():
    detector = Detector().fit(_make_normal_matrix())
    detector.set_decision_threshold(1.0)  # would flag nothing by default
    X = _make_far_outliers()
    flagged = detector.classify(X, threshold=0.0)  # everything clears 0.0
    assert flagged.sum() == len(X)


def test_set_decision_threshold_rejects_out_of_range():
    detector = Detector().fit(_make_normal_matrix())
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        detector.set_decision_threshold(1.5)
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        detector.set_decision_threshold(-0.1)


# --- predict_with_score() single-row shape ------------------------------


def test_predict_with_score_accepts_1d_row():
    detector = Detector().fit(_make_normal_matrix())
    result = detector.predict_with_score(_make_normal_matrix(n_rows=1)[0])
    assert set(result.keys()) == {"prediction", "anomaly_score"}
    assert isinstance(result["prediction"], int)
    assert isinstance(result["anomaly_score"], float)


def test_predict_with_score_accepts_2d_single_row():
    detector = Detector().fit(_make_normal_matrix())
    result = detector.predict_with_score(_make_normal_matrix(n_rows=1))
    assert isinstance(result["prediction"], int)
    assert isinstance(result["anomaly_score"], float)


def test_predict_with_score_rejects_multi_row_input():
    detector = Detector().fit(_make_normal_matrix())
    with pytest.raises(ValueError, match="exactly one row"):
        detector.predict_with_score(_make_normal_matrix(n_rows=5))


def test_predict_with_score_flags_far_outlier_at_permissive_threshold():
    detector = Detector().fit(_make_normal_matrix())
    detector.set_decision_threshold(0.01)
    result = detector.predict_with_score(_make_far_outliers(n_rows=1)[0])
    assert result["prediction"] == 1


# --- evaluate() — pure arithmetic on hand-built label arrays ------------


def test_evaluate_perfect_predictions():
    y_true = np.array([1, 1, 0, 0])
    y_pred = np.array([1, 1, 0, 0])
    metrics = Detector.evaluate(y_true, y_pred)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["fpr"] == 0.0
    assert (metrics["tp"], metrics["tn"], metrics["fp"], metrics["fn"]) == (2, 2, 0, 0)


def test_evaluate_confusion_counts():
    # 2 true attacks, one caught (TP) one missed (FN);
    # 2 true benign, one wrongly flagged (FP) one correct (TN).
    y_true = np.array([1, 1, 0, 0])
    y_pred = np.array([1, 0, 1, 0])
    metrics = Detector.evaluate(y_true, y_pred)
    assert metrics["tp"] == 1
    assert metrics["fn"] == 1
    assert metrics["fp"] == 1
    assert metrics["tn"] == 1
    assert metrics["recall"] == 0.5
    assert metrics["precision"] == 0.5
    assert metrics["fpr"] == 0.5


def test_evaluate_handles_no_positive_predictions():
    """Division-by-zero guard: if nothing is ever predicted positive,
    precision should default to 0.0, not raise or return NaN."""
    y_true = np.array([1, 1, 0, 0])
    y_pred = np.array([0, 0, 0, 0])
    metrics = Detector.evaluate(y_true, y_pred)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0


def test_evaluate_adjusted_precision_matches_manual_bayes_calculation():
    y_true = np.array([1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
    y_pred = np.array([1, 1, 0, 1, 0, 0, 0, 0, 0, 0])
    metrics = Detector.evaluate(y_true, y_pred, assumed_prevalence=0.196)

    recall = metrics["recall"]
    fpr = metrics["fpr"]
    p = 0.196
    expected = (p * recall) / (p * recall + (1 - p) * fpr)
    assert metrics["adjusted_precision"] == pytest.approx(expected)


def test_evaluate_does_not_require_a_fitted_model():
    """evaluate() is static — this is the whole point of that design:
    it should be callable with no Detector instance at all."""
    metrics = Detector.evaluate(np.array([1, 0]), np.array([1, 0]))
    assert metrics["precision"] == 1.0


# --- save/load round trip ------------------------------------------------


def test_save_load_round_trip_produces_identical_scores(tmp_path):
    detector = Detector().fit(_make_normal_matrix(), feature_names=["a", "b", "c", "d", "e", "f"])
    detector.set_decision_threshold(0.42)

    X = np.vstack([_make_normal_matrix(n_rows=10), _make_far_outliers(n_rows=10)])
    original_scores = detector.anomaly_score(X)

    path = tmp_path / "detector.pkl"
    detector.save(path)
    reloaded = Detector.load(path)
    reloaded_scores = reloaded.anomaly_score(X)

    assert np.allclose(original_scores, reloaded_scores)


def test_save_load_round_trip_preserves_decision_threshold(tmp_path):
    detector = Detector().fit(_make_normal_matrix())
    detector.set_decision_threshold(0.37)

    path = tmp_path / "detector.pkl"
    detector.save(path)
    reloaded = Detector.load(path)

    assert reloaded.decision_threshold == pytest.approx(0.37)


def test_save_load_round_trip_preserves_feature_names(tmp_path):
    names = ["a", "b", "c", "d", "e", "f"]
    detector = Detector().fit(_make_normal_matrix(), feature_names=names)

    path = tmp_path / "detector.pkl"
    detector.save(path)
    reloaded = Detector.load(path)

    assert reloaded.feature_names == names


def test_reloaded_detector_is_marked_fitted(tmp_path):
    detector = Detector().fit(_make_normal_matrix())
    path = tmp_path / "detector.pkl"
    detector.save(path)
    reloaded = Detector.load(path)
    assert reloaded.is_fitted is True


def test_reloaded_detector_preserves_config(tmp_path):
    detector = Detector(contamination=0.03, random_state=99)
    detector.fit(_make_normal_matrix())

    path = tmp_path / "detector.pkl"
    detector.save(path)
    reloaded = Detector.load(path)

    assert reloaded.contamination == 0.03
    assert reloaded.random_state == 99

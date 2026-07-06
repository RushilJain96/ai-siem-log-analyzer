"""Unit tests for model/features.py.

Uses hand-crafted synthetic DataFrames so behavior is deterministic
regardless of what CICIDS sample happens to be on disk. The real
CICIDS smoke test is scripts/fit_pipeline.py, which is not a test
(runs once, prints diagnostics) — this file is the CI-run correctness
suite.
"""
import numpy as np
import pandas as pd
import pytest

from model.features import FEATURE_COLUMNS, FeaturePipeline


def _make_benign_df(n_rows: int = 500) -> pd.DataFrame:
    """Produce a synthetic DataFrame with all feature columns.

    Values are deterministic across runs. Different columns get
    different scales so the standardization is meaningful.
    """
    rng = np.random.default_rng(seed=42)
    data = {
        name: rng.uniform(low=0, high=(i + 1) * 100, size=n_rows)
        for i, name in enumerate(FEATURE_COLUMNS)
    }
    return pd.DataFrame(data)


def test_fit_returns_self():
    pipeline = FeaturePipeline()
    result = pipeline.fit(_make_benign_df())
    assert result is pipeline


def test_is_fitted_flag_starts_false():
    pipeline = FeaturePipeline()
    assert pipeline.is_fitted is False


def test_is_fitted_flag_true_after_fit():
    pipeline = FeaturePipeline().fit(_make_benign_df())
    assert pipeline.is_fitted is True


def test_transform_before_fit_raises():
    pipeline = FeaturePipeline()
    with pytest.raises(RuntimeError, match="must be fit"):
        pipeline.transform(_make_benign_df())


def test_transform_returns_correct_shape():
    df = _make_benign_df(n_rows=200)
    pipeline = FeaturePipeline().fit(df)
    result = pipeline.transform(df)
    assert result.shape == (200, len(FEATURE_COLUMNS))


def test_transformed_benign_is_zero_mean_unit_std():
    """After fitting on benign data, transforming that same data
    should yield approximately zero mean and unit std per column."""
    df = _make_benign_df(n_rows=1000)
    pipeline = FeaturePipeline().fit(df)
    transformed = pipeline.transform(df)

    means = transformed.mean(axis=0)
    stds = transformed.std(axis=0)

    assert np.allclose(means, 0, atol=1e-6)
    assert np.allclose(stds, 1, atol=1e-2)


def test_fit_on_too_few_rows_raises():
    df = _make_benign_df(n_rows=50)
    pipeline = FeaturePipeline()
    with pytest.raises(ValueError, match="degenerate"):
        pipeline.fit(df)


def test_transform_handles_inf_via_median_imputation():
    """inf values in input should be replaced with medians, not
    propagated to output."""
    df = _make_benign_df(n_rows=500)
    pipeline = FeaturePipeline().fit(df)

    # Introduce inf into every column of a fresh row.
    dirty = _make_benign_df(n_rows=1).copy()
    for col in FEATURE_COLUMNS:
        dirty.at[0, col] = np.inf

    result = pipeline.transform(dirty)
    assert result.shape == (1, len(FEATURE_COLUMNS))
    assert not np.isinf(result).any()
    assert not np.isnan(result).any()


def test_transform_handles_nan_via_median_imputation():
    df = _make_benign_df(n_rows=500)
    pipeline = FeaturePipeline().fit(df)

    dirty = _make_benign_df(n_rows=1).copy()
    for col in FEATURE_COLUMNS:
        dirty.at[0, col] = np.nan

    result = pipeline.transform(dirty)
    assert not np.isnan(result).any()


def test_to_file_before_fit_raises(tmp_path):
    pipeline = FeaturePipeline()
    with pytest.raises(RuntimeError, match="unfitted"):
        pipeline.to_file(tmp_path / "should_not_be_written.pkl")


def test_from_file_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        FeaturePipeline.from_file(tmp_path / "nonexistent.pkl")


def test_save_load_round_trip_is_identical(tmp_path):
    """A fitted pipeline saved and reloaded should produce identical
    transforms — this is the training/serving skew guarantee."""
    df = _make_benign_df(n_rows=500)
    pipeline = FeaturePipeline().fit(df)
    original_output = pipeline.transform(df)

    path = tmp_path / "pipeline.pkl"
    pipeline.to_file(path)
    reloaded = FeaturePipeline.from_file(path)
    reloaded_output = reloaded.transform(df)

    assert np.allclose(original_output, reloaded_output)


def test_reloaded_pipeline_is_marked_fitted(tmp_path):
    df = _make_benign_df(n_rows=500)
    pipeline = FeaturePipeline().fit(df)

    path = tmp_path / "pipeline.pkl"
    pipeline.to_file(path)
    reloaded = FeaturePipeline.from_file(path)

    assert reloaded.is_fitted is True
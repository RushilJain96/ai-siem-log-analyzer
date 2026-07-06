"""Feature engineering pipeline for CICIDS 2017 flow data.

Owns the translation from a DataFrame of parsed CICIDS rows into the
feature matrix consumed by the Isolation Forest detector.

Design contract:
- fit() is called ONCE on benign rows during offline training (Day 3).
- transform() is called MANY times — at evaluation time and, on Day 5,
  at inference time on incoming logs via /logs/ingest.
- The fitted pipeline is persisted to disk via to_file() and loaded at
  runtime via from_file(). Same object serves training and inference,
  preventing training/serving skew.

Design decisions documented in the module docstring so that interview
prep answers can be traced back to code:

1. Feature selection: 15 flow-shape features covering volume, rate,
   packet size, and timing. Excludes destination port (categorical),
   flag counts (mostly near-zero), and duplicated columns. Automated
   feature selection is a v2.0 improvement.

2. Fit on benign only: anomaly detection convention. Attack rows are
   never seen during fit; they SHOULD look shifted after transform.

3. StandardScaler over MinMaxScaler: our data has extreme outliers
   (e.g., max Flow IAT Std ~6M vs mean ~1.6M). MinMaxScaler would
   compress most rows into a tiny sliver of [0, 1].

4. inf/NaN at fit time: rows with any inf or NaN in the feature
   columns are DROPPED. Costs ~0.2% of benign rows; simpler than
   percentile capping.

5. inf/NaN at transform time: replaced with per-column MEDIANS
   learned during fit. Preserved as pipeline state.
"""
from __future__ import annotations

from pathlib import Path
from typing import Self

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS: list[str] = [
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Max Packet Length",
    "Min Packet Length",
    "Flow Duration",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
]


class FeaturePipeline:
    """Fit-once, transform-many preprocessing for CICIDS flow features.

    Attributes populated by fit():
        medians: per-column median values, used to impute inf/NaN
            at transform time.
        scaler: fitted StandardScaler holding per-column mean and std.
        is_fitted: True after fit() succeeds.
    """

    def __init__(self) -> None:
        self.feature_columns: list[str] = list(FEATURE_COLUMNS)
        self.medians: pd.Series | None = None
        self.scaler: StandardScaler | None = None
        self.is_fitted: bool = False

    def fit(self, df: pd.DataFrame) -> Self:
        """Learn medians and scaling parameters from benign rows.

        The caller is responsible for passing only benign rows. This
        method does NOT filter by label — separation of concerns.

        Args:
            df: DataFrame containing at least self.feature_columns.
                Column names must have whitespace already stripped.

        Returns:
            self (for method chaining).

        Raises:
            KeyError: if any expected feature column is missing.
            ValueError: if fewer than 100 rows survive inf/NaN removal
                (guardrail against fitting on a degenerate sample).
        """
        X = df[self.feature_columns].astype(float)

        # Replace inf with NaN so we can drop both categories in one call.
        X = X.replace([np.inf, -np.inf], np.nan)
        clean = X.dropna()

        if len(clean) < 100:
            raise ValueError(
                f"Only {len(clean)} clean rows available for fitting; "
                f"refusing to fit a degenerate scaler."
            )

        # Learn medians from the CLEAN data. These will be used to
        # impute inf/NaN at transform time.
        self.medians = clean.median()

        # Fit the scaler on the same clean data.
        self.scaler = StandardScaler()
        self.scaler.fit(clean.values)

        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Apply the fitted pipeline to a DataFrame.

        Args:
            df: DataFrame containing at least self.feature_columns.
                May include rows with inf or NaN — these are imputed
                with the learned medians before scaling.

        Returns:
            2D numpy array of shape (n_rows, n_features). Column order
            matches self.feature_columns.

        Raises:
            RuntimeError: if called before fit().
        """
        if not self.is_fitted:
            raise RuntimeError("Pipeline must be fit before transform.")

        X = df[self.feature_columns].astype(float).copy()
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(self.medians)

        return self.scaler.transform(X.values)

    def to_file(self, path: Path | str) -> None:
        """Persist the fitted pipeline to disk via joblib.

        joblib is preferred over pickle for objects containing numpy
        arrays: it stores arrays out-of-band which is faster and more
        space-efficient for scikit-learn estimators.

        Raises:
            RuntimeError: if called before fit().
        """
        if not self.is_fitted:
            raise RuntimeError("Cannot persist an unfitted pipeline.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def from_file(cls, path: Path | str) -> FeaturePipeline:
        """Load a fitted pipeline from disk.

        Returns a FeaturePipeline instance with is_fitted=True. Callers
        can immediately call transform() on the returned object.

        Raises:
            FileNotFoundError: if the path doesn't exist.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"No fitted pipeline at {path}")
        return joblib.load(path)
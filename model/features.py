"""Feature engineering pipeline for CICIDS 2017 flow data.

Owns the translation from a DataFrame of parsed CICIDS rows into the
feature matrix consumed by the Isolation Forest detector.

Design contract:
- fit() is called ONCE on benign-only rows during offline training (Day 3/4).
- transform() is called MANY times — at evaluation time on Day 4, and at
  live single-row inference from /logs/ingest on Day 5.
- The fitted pipeline is persisted via save() and loaded at runtime via
  load(). Same object serves training and inference, preventing
  training/serving skew.

Design decisions (numbered so interview answers can trace to code):

1. Feature selection: 18 flow-shape features — timing, rates, directional
   packet-size statistics, TCP flag counts, TCP window sizes, down/up ratio.
   Directional packet stats (Fwd/Bwd Packet Length Mean/Std) preferred over
   aggregate stats because network attacks are asymmetric (DoS floods send
   large packets, receive tiny ones; exfiltration sends small requests,
   receives large responses). TCP flag counts (SYN/ACK/RST/PSH) added
   because they expose connection-state behavior: SYN floods, port scans,
   and ACK floods have characteristic flag signatures. Automated selection
   via mutual information is a v2.0 improvement.

2. Fit on benign only: anomaly detection convention. The model learns
   'what does normal look like?' Attack rows are never seen during fit —
   they SHOULD look shifted after transform, which is what we measure.

3. StandardScaler over MinMaxScaler: CICIDS data has extreme outliers
   (Flow IAT Std max ~6M vs mean ~1.6M). MinMaxScaler would compress most
   rows into a tiny sliver of [0, 1] due to these outliers.

4. inf/NaN at fit time: rows are DROPPED (costs ~0.2% of benign rows;
   simpler than percentile capping). At transform time: IMPUTED with
   per-column medians learned during fit (cannot drop a single live row
   at inference time).

5. Persistence: joblib not pickle — joblib stores numpy arrays out-of-band,
   faster and more space-efficient for sklearn estimators.
"""

from __future__ import annotations

from pathlib import Path
from typing import Self

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


# 18 columns, grouped by what they capture.
# In the 56,614-row sample, only Flow Bytes/s and Flow Packets/s
# carry inf/NaN (32 and 46 rows in the benign subset respectively —
# verified by Day 3's tmpload.py inspection). Everything else is clean.
FEATURE_COLUMNS: list[str] = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow IAT Mean",
    "Flow IAT Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Down/Up Ratio",
]


class FeaturePipeline:
    """Fit-once, transform-many preprocessing for CICIDS flow features.

    fit() drops rows with inf/NaN outright (batch-only operation, cheap
    to lose ~0.1-0.2% of benign rows). transform() never drops rows —
    it imputes inf/NaN with the medians learned during fit, because
    transform must also work on a single live row where "dropping" isn't
    a meaningful operation (you can't return nothing to a caller who
    submitted one log). One rule for both call sites, not two.
    """

    def __init__(self) -> None:
        self.feature_columns: list[str] = list(FEATURE_COLUMNS)
        self.medians: pd.Series | None = None
        self.scaler: StandardScaler | None = None
        self.is_fitted: bool = False

    def fit(self, df: pd.DataFrame) -> Self:
        """Learn medians and scaling parameters from benign rows.

        The caller is responsible for passing only benign rows — this
        method does NOT filter by label itself. That's a deliberate
        separation of concerns: this class owns "how to normalize,"
        not "which rows count as normal." Mixing those would make it
        harder to test each independently.

        Raises:
            KeyError: if any expected feature column is missing from df.
            ValueError: if fewer than 100 rows survive inf/NaN removal
                (guardrail against silently fitting a degenerate scaler
                on too small or badly-filtered a sample).
        """
        X = df[self.feature_columns].astype(float)

        # inf has no NaN-detecting method of its own in pandas, so we
        # convert both +inf and -inf into NaN first, then one dropna()
        # call catches everything at once.
        X = X.replace([np.inf, -np.inf], np.nan)
        clean = X.dropna()

        if len(clean) < 100:
            raise ValueError(
                f"Only {len(clean)} clean rows available for fitting; "
                f"refusing to fit a degenerate scaler."
            )

        # Medians come from the CLEAN benign data only — these are what
        # transform() will later use to patch inf/NaN in live rows.
        self.medians = clean.median()

        self.scaler = StandardScaler()
        self.scaler.fit(clean.values)

        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Apply the fitted pipeline to any DataFrame — benign, attack,
        a full batch, or a single live row.

        inf/NaN in the input are imputed with the medians learned at
        fit time, never dropped, so this method always returns exactly
        as many rows as it received.

        Raises:
            RuntimeError: if called before fit().
        """
        if not self.is_fitted:
            raise RuntimeError("Pipeline must be fit before transform.")

        X = df[self.feature_columns].astype(float).copy()
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(self.medians)

        return self.scaler.transform(X.values)

    def save(self, path: Path | str) -> None:
        """Persist the fitted pipeline to disk via joblib.

        joblib (not raw pickle) because it stores numpy arrays
        out-of-band, which is faster and smaller for objects holding
        sklearn estimators like our StandardScaler.

        Raises:
            RuntimeError: if called before fit() — an unfitted pipeline
                on disk would silently produce garbage at load time.
        """
        if not self.is_fitted:
            raise RuntimeError("Cannot persist an unfitted pipeline.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: Path | str) -> FeaturePipeline:
        """Load a fitted pipeline from disk. Returned object is ready
        for transform() immediately — no re-fitting needed.

        Raises:
            FileNotFoundError: if the path doesn't exist.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"No fitted pipeline at {path}")
        return joblib.load(path)
"""Isolation Forest anomaly detector for CICIDS flow features.

Consumes the feature matrix produced by model.features.FeaturePipeline.
Owns the anomaly model itself, plus everything needed to turn its raw
output into an operational decision: a calibrated [0, 1] anomaly score
and a persisted alert threshold.

Design contract:
- fit() is called ONCE, on the SCALED, BENIGN-ONLY output of
  FeaturePipeline.transform() (offline training, Day 4).
- predict() / anomaly_score() / classify() are called MANY times — at
  evaluation time here, and at live single-row inference from
  /logs/ingest on Day 5 (via predict_with_score()).
- The fitted detector is persisted via save() and loaded via load().

Design decisions (numbered so interview answers can trace to code):

1. contamination=0.01, not the project doc's 0.1: contamination is
   sklearn's *prior* on how much of the FIT data is already
   contaminated with anomalies — not an estimate of real-world attack
   prevalence (~19.6% here). We fit on benign-only rows, so the only
   contamination expected is label noise (CICIDS mislabeling, benign
   flows that look attack-like). 1% is a small, deliberate allowance
   for that noise, not a claim about how common attacks are in
   production traffic. Conflating the two is a common mistake.

2. IsolationForest is (re)built fresh inside fit(), never in __init__:
   __init__ stores configuration (contamination, random_state);
   fit() owns the fitted state. Building the estimator in __init__
   would let a caller inspect or reuse a "fitted-looking" object
   before fit() ever ran, and would make re-fitting the same Detector
   instance silently reuse stale internal tree state instead of
   starting clean.

3. anomaly_score() calibration: sklearn's decision_function() is
   unbounded and NOT centered at a fixed, meaningful number across
   datasets — its scale depends on the data itself. We convert it to
   a [0, 1] score via a sigmoid, calibrated using the TRAINING data's
   own decision_function spread (SIGMOID_SPREAD_STDS=4.0 / train_std),
   so 0.5 always means "sklearn's own inlier/outlier boundary"
   regardless of dataset scale. Sigmoid over min-max scaling because
   min-max needs a fixed min/max range observed at fit time — test-set
   attacks routinely fall outside that range, which would either
   require clipping (saturating many different attacks to an
   indistinguishable 1.0) or silently extrapolate past [0, 1].
   A sigmoid degrades gracefully for unseen extremes instead.

4. decision_threshold is a persisted attribute, separate from
   contamination: contamination shapes how the forest partitions
   during TRAINING (a training-time prior). decision_threshold is
   the OPERATIONAL cutoff applied to anomaly_score() at inference
   time, tuned after training against a business/ops constraint
   (e.g. an FPR budget). Decoupling them means the alert threshold
   can be re-tuned without retraining the model.

5. evaluate() is a static method: it is pure arithmetic over
   (y_true, y_pred) label arrays — it needs no fitted model at all.
   Making it static means threshold-tuning math can be tested with
   hand-built label arrays, independent of ever training a real
   forest. Returns adjusted_precision alongside raw precision because
   CICIDS's ~19.6% attack prevalence in the labeled sample is an
   artifact of how the dataset was assembled, not a claim about real
   traffic — adjusted_precision reweights via Bayes' rule using an
   assumed real-world prevalence, so the number reported is honest
   about what "precision in production" would actually look like.

6. save() persists a plain dict payload, not the whole Detector
   object (joblib.dump(self)) the way FeaturePipeline does. This is
   a deliberate but not yet reconciled inconsistency between the two
   modules — tracked as backlog, not a design endorsement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Self

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

SCHEMA_VERSION = 1
MIN_TRAINING_ROWS = 100


class Detector:
    """Fit-once, predict-many Isolation Forest wrapper.

    All prediction methods operate on the SCALED feature matrix
    produced by FeaturePipeline.transform() — this class has no
    knowledge of raw CICIDS columns or units.
    """

    DEFAULT_CONTAMINATION = 0.01
    SIGMOID_SPREAD_STDS = 4.0

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state

        self.model: IsolationForest | None = None
        self.n_features: int | None = None
        self.feature_names: list[str] | None = None
        self.score_scale: float | None = None
        self.decision_threshold: float = 0.5
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, feature_names: list[str] | None = None) -> Self:
        """Fit a fresh IsolationForest on already-scaled, benign-only rows.

        Also calibrates score_scale from the training data's own
        decision_function spread, so anomaly_score() is meaningful
        immediately after fit() with no separate calibration step.

        Raises:
            ValueError: if X is not 2D, has fewer than
                MIN_TRAINING_ROWS rows, or contains non-finite values
                (fit() trusts its caller to have already cleaned data
                via FeaturePipeline — this is a guardrail, not a
                cleaning step).
        """
        X = np.asarray(X, dtype=float)

        if X.ndim != 2:
            raise ValueError(f"X must be 2D, got shape {X.shape}")
        if X.shape[0] < MIN_TRAINING_ROWS:
            raise ValueError(
                f"Only {X.shape[0]} training rows provided; "
                f"refusing to fit on fewer than {MIN_TRAINING_ROWS}."
            )
        if not np.isfinite(X).all():
            raise ValueError(
                "X contains inf/NaN. Detector.fit() expects already-"
                "cleaned data (see FeaturePipeline.transform())."
            )

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X)

        self.n_features = X.shape[1]
        self.feature_names = list(feature_names) if feature_names else None

        train_scores = self.model.decision_function(X)
        train_std = train_scores.std()
        self.score_scale = self.SIGMOID_SPREAD_STDS / train_std

        self.is_fitted = True
        return self

    def _check_fitted(self) -> None:
        if not self.is_fitted:
            raise RuntimeError("Detector must be fit before this call.")

    def _check_shape(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        if X.ndim != 2:
            raise ValueError(f"X must be 2D, got shape {X.shape}")
        if X.shape[1] != self.n_features:
            raise ValueError(
                f"X has {X.shape[1]} features; detector was fit on "
                f"{self.n_features}."
            )
        return X

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Raw contamination-based prediction: 1 = anomaly, 0 = normal.

        Remaps sklearn's native {-1, +1} (outlier, inlier) into our
        {1, 0} (anomaly, normal) convention, matching the rest of the
        codebase where 1 always means "flag this."
        """
        self._check_fitted()
        X = self._check_shape(X)
        raw = self.model.predict(X)
        return (raw == -1).astype(int)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Calibrated anomaly score in (0, 1). 0.5 = the model's own
        inlier/outlier boundary; higher = more anomalous.

        decision_function() is LOWER for outliers, so we negate before
        the sigmoid to get the intuitive "higher = more anomalous"
        direction.
        """
        self._check_fitted()
        X = self._check_shape(X)
        raw = self.model.decision_function(X)
        return 1.0 / (1.0 + np.exp(raw * self.score_scale))

    def classify(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        """Operational classification: anomaly_score() >= threshold.

        Uses self.decision_threshold by default, not contamination —
        this is the tuned operational alert boundary, independent of
        whatever contamination the forest was trained with.
        """
        if threshold is None:
            threshold = self.decision_threshold
        scores = self.anomaly_score(X)
        return (scores >= threshold).astype(int)

    def predict_with_score(self, X: np.ndarray) -> dict:
        """Single-row inference shape for live use (Day 5 /logs/ingest):
        one feature row in, one {"prediction", "anomaly_score"} result
        out, as plain Python scalars (JSON-serializable, no numpy
        types leaking into the API layer).

        Accepts either a 1D array of length n_features or a 2D array
        with exactly one row.

        Raises:
            ValueError: if X does not represent exactly one row.
        """
        self._check_fitted()
        X = np.asarray(X, dtype=float)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.ndim != 2 or X.shape[0] != 1:
            raise ValueError(
                "predict_with_score expects exactly one row "
                f"(shape (n_features,) or (1, n_features)), got {X.shape}"
            )
        X = self._check_shape(X)

        score = float(self.anomaly_score(X)[0])
        prediction = int(score >= self.decision_threshold)
        return {"prediction": prediction, "anomaly_score": score}

    def set_decision_threshold(self, threshold: float) -> None:
        """Update the operational alert threshold used by classify()
        and predict_with_score().

        Raises:
            ValueError: if threshold is outside [0, 1] — anomaly_score()
                never produces values outside that range, so a
                threshold outside it would be dead configuration
                (either always or never fires).
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {threshold}")
        self.decision_threshold = threshold

    @staticmethod
    def evaluate(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        assumed_prevalence: float = 0.196,
    ) -> dict:
        """Compute classification metrics from label arrays.

        1 = anomaly/attack, 0 = normal/benign, for both arrays.

        assumed_prevalence corrects for evaluation sets that don't
        reflect real-world attack prevalence (ours is ~55/45 by
        construction — all attack rows are test-only, and benign is
        just the 20% held-out split). adjusted_precision reweights
        precision via Bayes' rule as if the real-world prevalence were
        assumed_prevalence instead of whatever ratio happens to be in
        y_true:

            adjusted_precision = (p * recall) / (p * recall + (1 - p) * FPR)

        where p = assumed_prevalence. Static because this is pure
        arithmetic over label arrays — no fitted model required, which
        is what makes it directly testable with hand-built arrays.
        """
        y_true = np.asarray(y_true)
        y_pred = np.asarray(y_pred)

        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        p = assumed_prevalence
        adjusted_denominator = p * recall + (1 - p) * fpr
        adjusted_precision = (
            (p * recall) / adjusted_denominator if adjusted_denominator > 0 else 0.0
        )

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "adjusted_precision": adjusted_precision,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        }

    def save(self, path: Path | str) -> None:
        """Persist as a plain dict payload (see class docstring, point 6).

        Raises:
            RuntimeError: if called before fit().
        """
        self._check_fitted()

        payload = {
            "model": self.model,
            "config": {
                "contamination": self.contamination,
                "random_state": self.random_state,
            },
            "score_scale": self.score_scale,
            "n_features": self.n_features,
            "decision_threshold": self.decision_threshold,
            "metadata": {
                "model_type": "IsolationForest",
                "schema_version": SCHEMA_VERSION,
                "trained_at": datetime.now(timezone.utc).isoformat(),
                "feature_names": self.feature_names,
            },
        }

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(payload, path)

    @classmethod
    def load(cls, path: Path | str) -> Detector:
        """Load a fitted detector from a dict payload written by save().

        Raises:
            FileNotFoundError: if the path doesn't exist.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"No fitted detector at {path}")

        payload = joblib.load(path)

        detector = cls(
            contamination=payload["config"]["contamination"],
            random_state=payload["config"]["random_state"],
        )
        detector.model = payload["model"]
        detector.score_scale = payload["score_scale"]
        detector.n_features = payload["n_features"]
        detector.decision_threshold = payload["decision_threshold"]
        detector.feature_names = payload["metadata"]["feature_names"]
        detector.is_fitted = True
        return detector

"""Live inference for POST /logs/ingest (Day 5).

Composes a fitted FeaturePipeline + Detector into a single "score one
raw feature dict" operation. Neither FeaturePipeline nor Detector know
about each other or about HTTP -- this module is the seam between them
and the API layer.

Design decisions:

1. AnomalyScorer takes already-loaded FeaturePipeline/Detector objects
   in __init__, not file paths. Loading from disk is a separate concern
   (load_default()) -- this keeps the scoring logic itself trivially
   testable with synthetic in-memory fitted objects, no .pkl files
   needed, consistent with how tests/test_detector.py never touches
   real files either.

2. score() accepts a PARTIAL features dict. Missing keys become NaN and
   fall through to FeaturePipeline.transform()'s existing median
   imputation -- logic built in Day 3 specifically for "a single live
   row can't be dropped." A log source with incomplete flow stats still
   gets a best-effort score instead of a hard rejection, for free.

3. load_default() raises FileNotFoundError if either artifact is
   missing, matching FeaturePipeline.load()/Detector.load()'s existing
   convention -- consistent, not surprising. Whether "no trained model
   available" should be a hard startup failure or a graceful skip is an
   APPLICATION policy decision, not this module's job: that's why the
   try/except around load_default() lives in api/main.py's lifespan,
   not here.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from model.detector import Detector
from model.features import FeaturePipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PIPELINE_PATH = PROJECT_ROOT / "model" / "preprocessor.pkl"
DEFAULT_DETECTOR_PATH = PROJECT_ROOT / "model" / "isolation_forest.pkl"


class AnomalyScorer:
    """A fitted FeaturePipeline + Detector, composed into one scoring call."""

    def __init__(self, pipeline: FeaturePipeline, detector: Detector) -> None:
        self.pipeline = pipeline
        self.detector = detector

    TOP_FEATURE_COUNT = 5

    def score(self, features: dict[str, float]) -> dict:
        """Score one raw feature dict.

        Keys missing from `features` are imputed by the pipeline's
        fit-time medians, same as any other NaN value would be.

        `top_features` is an interpretable PROXY for why a row looks
        anomalous — NOT the Isolation Forest's internal attribution.
        The forest decides via path length across random splits; there's
        no per-feature contribution in that mechanism. What we compute
        instead: the pipeline scales every feature to mean-0/std-1 on
        BENIGN traffic, so a feature's scaled value is its distance from
        the benign baseline in standard deviations. The features with the
        largest absolute scaled value are the ones furthest from normal,
        which is a genuinely useful analyst signal ("Bwd Packet Length
        Std is +4.1σ above the learned baseline") — just don't mistake it
        for SHAP-style model attribution. True IF attribution would need
        a separate explainer (a v2.0 item).

        Returns:
            {"is_alert": bool, "anomaly_score": float,
             "top_features": [{"feature": str, "deviation": float}, ...]}
        """
        row = {
            col: features.get(col, np.nan) for col in self.pipeline.feature_columns
        }
        df = pd.DataFrame([row])
        X = self.pipeline.transform(df)
        result = self.detector.predict_with_score(X)

        scaled = X[0]
        ranked = sorted(
            zip(self.pipeline.feature_columns, scaled),
            key=lambda pair: abs(pair[1]),
            reverse=True,
        )
        top_features = [
            {"feature": name, "deviation": round(float(value), 2)}
            for name, value in ranked[: self.TOP_FEATURE_COUNT]
        ]

        return {
            "is_alert": bool(result["prediction"]),
            "anomaly_score": result["anomaly_score"],
            "top_features": top_features,
        }

    @classmethod
    def load_default(
        cls,
        pipeline_path: Path | str = DEFAULT_PIPELINE_PATH,
        detector_path: Path | str = DEFAULT_DETECTOR_PATH,
    ) -> AnomalyScorer:
        """Load both fitted artifacts from their standard locations.

        Raises:
            FileNotFoundError: if either artifact is missing (propagated
                unchanged from FeaturePipeline.load()/Detector.load()).
                Callers decide what "missing" means for them.
        """
        pipeline = FeaturePipeline.load(pipeline_path)
        detector = Detector.load(detector_path)
        return cls(pipeline, detector)
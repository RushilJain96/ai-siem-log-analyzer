"""Train the Isolation Forest anomaly detector on CICIDS benign flows.

Loads the already-fitted FeaturePipeline (never refits it — refitting
here would let this script's scaler drift from whatever Day 5's live
ingest loads at inference time, silently reintroducing training/
serving skew). Splits ONLY the benign rows 80/20; every attack row is
held out for evaluation only — the model must never see an attack
during fit(), by anomaly-detection convention (see features.py).

Also tunes the operational decision_threshold: the raw contamination
(0.01) governs training, not alerting. We sweep thresholds via
sklearn's roc_curve and pick the one that maximizes recall subject to
an FPR budget (attacker recall matters, but not at the cost of
drowning analysts in false positives).

Run once from anywhere:
    python -m scripts.train_detector

Output artifacts (both committed as the approved model release):
    model/isolation_forest.pkl  the fitted detector
    model/model_card.json       the release record — provenance, evaluation,
                                  runtime versions, and each artifact's
                                  SHA-256 (verified at load time). Replaces
                                  the old metrics.json.

Pass --artifact-version to stamp the release (default below).
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve
from sklearn.model_selection import train_test_split

from model.artifact_integrity import sha256_file, write_model_card
from model.detector import Detector
from model.features import FeaturePipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PATH = PROJECT_ROOT / "data" / "raw" / "cicids_sample.csv"
PIPELINE_PATH = PROJECT_ROOT / "model" / "preprocessor.pkl"
DETECTOR_PATH = PROJECT_ROOT / "model" / "isolation_forest.pkl"
CARD_PATH = PROJECT_ROOT / "model" / "model_card.json"

FPR_BUDGET = 0.05
# Human-set semantic version for the trained model. Bump when you retrain
# and intend to ship a new approved model. Recorded in the card.
ARTIFACT_VERSION = "v1.0.0"


def main(artifact_version: str = ARTIFACT_VERSION) -> None:
    if not SAMPLE_PATH.exists():
        raise SystemExit(
            f"Sample not found at {SAMPLE_PATH}\n"
            f"Run scripts/sample_cicids.py first."
        )
    if not PIPELINE_PATH.exists():
        raise SystemExit(
            f"No fitted pipeline at {PIPELINE_PATH}\n"
            f"Run scripts/fit_pipeline.py first."
        )

    print(f"Loading sample from {SAMPLE_PATH.name}...")
    df = pd.read_csv(SAMPLE_PATH)
    df.columns = df.columns.str.strip()
    labels = df["Label"].str.strip()
    benign = df[labels == "BENIGN"]
    attack = df[labels != "BENIGN"]
    print(f"  Benign: {len(benign)} rows | Attack: {len(attack)} rows")

    print(f"\nLoading fitted preprocessor from {PIPELINE_PATH.name}...")
    pipeline = FeaturePipeline.load(PIPELINE_PATH)

    print("\nSplitting benign rows 80/20 (train/test)...")
    benign_train, benign_test = train_test_split(
        benign, test_size=0.2, shuffle=True, random_state=42,
    )
    print(f"  benign_train: {len(benign_train)} | benign_test: {len(benign_test)}")
    print(f"  attack rows are 100% test-only: {len(attack)}")

    X_train = pipeline.transform(benign_train)
    X_benign_test = pipeline.transform(benign_test)
    X_attack_test = pipeline.transform(attack)

    print("\nFitting Detector on benign_train...")
    detector = Detector().fit(X_train, feature_names=pipeline.feature_columns)

    # Sanity check, not a quality check: ~contamination fraction of the
    # TRAINING rows should self-flag under the raw predict() convention.
    # This only confirms fit() behaved as configured, before any time is
    # spent on threshold tuning below.
    train_preds = detector.predict(X_train)
    self_flag_rate = float(train_preds.mean())
    print(
        f"  Sanity check: {self_flag_rate:.4%} of training rows self-flag "
        f"(contamination={detector.contamination:.2%})"
    )

    print("\nBuilding evaluation set (benign_test + attack_test)...")
    X_eval = np.vstack([X_benign_test, X_attack_test])
    y_eval = np.concatenate([
        np.zeros(len(X_benign_test), dtype=int),
        np.ones(len(X_attack_test), dtype=int),
    ])
    print(
        f"  eval set: {len(X_eval)} rows "
        f"({len(X_benign_test)} benign + {len(X_attack_test)} attack)"
    )

    eval_scores = detector.anomaly_score(X_eval)

    print(
        f"\nTuning decision_threshold: maximize recall subject to "
        f"FPR <= {FPR_BUDGET:.0%}..."
    )
    fpr, tpr, thresholds = roc_curve(y_eval, eval_scores)
    within_budget = fpr <= FPR_BUDGET
    if not within_budget.any():
        raise SystemExit(
            f"No threshold on this eval set achieves FPR <= {FPR_BUDGET:.0%}; "
            f"widen FPR_BUDGET or investigate the model."
        )
    best_index = np.argmax(tpr[within_budget])
    tuned_threshold = float(thresholds[within_budget][best_index])
    detector.set_decision_threshold(tuned_threshold)
    print(f"  tuned decision_threshold = {tuned_threshold:.4f}")

    eval_preds = detector.classify(X_eval)
    metrics = Detector.evaluate(y_eval, eval_preds)
    print("\nEvaluation at tuned threshold:")
    for key in ("precision", "recall", "f1", "fpr", "adjusted_precision"):
        print(f"  {key:<18} {metrics[key]:.4f}")
    print(
        f"  tp={metrics['tp']} tn={metrics['tn']} "
        f"fp={metrics['fp']} fn={metrics['fn']}"
    )

    print(f"\nSaving fitted detector to {DETECTOR_PATH}...")
    detector.save(DETECTOR_PATH)
    size_kb = DETECTOR_PATH.stat().st_size / 1024
    print(f"  Wrote {size_kb:.1f} KB.")

    # Write the model card LAST — after both artifacts are on disk — so it
    # hashes the exact (preprocessor, detector) pair this run produced and
    # binds them together. It is the single machine-readable release record
    # (it replaces the old metrics.json): provenance + evaluation + the
    # SHA-256s the app verifies before loading. See model/artifact_integrity.
    print(f"\nWriting model card to {CARD_PATH}...")
    card = write_model_card(
        CARD_PATH,
        artifacts={
            "preprocessor.pkl": PIPELINE_PATH,
            "isolation_forest.pkl": DETECTOR_PATH,
        },
        artifact_version=artifact_version,
        training={
            "dataset": "CICIDS2017 sampled dataset",
            "random_state": detector.random_state,
            "feature_count": len(pipeline.feature_columns),
            "feature_names": list(pipeline.feature_columns),
            "n_estimators": detector.model.n_estimators,
            "contamination": detector.contamination,
        },
        evaluation={
            "decision_threshold": tuned_threshold,
            "fpr_budget": FPR_BUDGET,
            "eval_set": {
                "benign_test": len(X_benign_test),
                "attack_test": len(X_attack_test),
            },
            "metrics": metrics,
            "sanity_check_self_flag_rate": self_flag_rate,
        },
        training_data={
            "path": str(SAMPLE_PATH.relative_to(PROJECT_ROOT)).replace("\\", "/"),
            "sha256": sha256_file(SAMPLE_PATH),
        },
        limitations=[
            "Trained and evaluated on a sampled subset of CICIDS2017, not the "
            "full capture.",
            "Isolation Forest anomaly scores are not probabilities of "
            "maliciousness (the score scale is calibrated, but it is not a "
            "probability).",
            "Dashboard source-IP locations are simulated until GeoIP "
            "enrichment is implemented.",
        ],
    )
    print(
        f"  {artifact_version} · detector sha256 "
        f"{card['artifacts']['isolation_forest.pkl']['sha256'][:12]}…"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train and release the SIEM Isolation Forest detector."
    )
    parser.add_argument(
        "--artifact-version",
        default=ARTIFACT_VERSION,
        help=f"Version stamped into model_card.json (default: {ARTIFACT_VERSION})",
    )
    args = parser.parse_args()
    main(artifact_version=args.artifact_version)

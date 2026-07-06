"""Fit the CICIDS feature pipeline on benign rows from the sample.

Reads data/raw/cicids_sample.csv, splits into benign/attack, fits
FeaturePipeline on the benign rows only, and persists the fitted
object to model/preprocessor.pkl.

Also prints per-column mean/std of transformed benign vs attack data,
so we can verify the pipeline discriminates before moving on to Day 4.

Run once from the project root:
    python -m scripts.fit_pipeline

Output artifact: model/preprocessor.pkl (gitignored; each developer
regenerates locally). Same script re-run produces byte-identical output
given the same input, because the pipeline itself is deterministic.
"""
from pathlib import Path

import numpy as np
import pandas as pd

from model.features import FEATURE_COLUMNS, FeaturePipeline


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PATH = PROJECT_ROOT / "data" / "raw" / "cicids_sample.csv"
PIPELINE_PATH = PROJECT_ROOT / "model" / "preprocessor.pkl"


def main() -> None:
    if not SAMPLE_PATH.exists():
        raise SystemExit(
            f"Sample not found at {SAMPLE_PATH}\n"
            f"Run scripts/sample_cicids.py first."
        )

    print(f"Loading sample from {SAMPLE_PATH.name}...")
    df = pd.read_csv(SAMPLE_PATH)
    df.columns = df.columns.str.strip()
    print(f"  Loaded {len(df)} rows, {len(df.columns)} columns.")

    labels = df["Label"].str.strip()
    benign = df[labels == "BENIGN"]
    attack = df[labels != "BENIGN"]
    print(f"  Benign: {len(benign)} rows | Attack: {len(attack)} rows")

    print("\nFitting pipeline on benign rows...")
    pipeline = FeaturePipeline().fit(benign)
    print(f"  Fitted. Learned medians for {len(pipeline.medians)} features.")
    print(f"  Scaler mean shape: {pipeline.scaler.mean_.shape}")

    print("\nTransforming benign and attack subsets for sanity check...")
    X_benign_scaled = pipeline.transform(benign)
    X_attack_scaled = pipeline.transform(attack)

    print("\nPer-feature stats after scaling (mean ± std):")
    print(f"{'feature':<32} {'benign':<25} {'attack':<25}")
    print("-" * 82)
    for i, name in enumerate(FEATURE_COLUMNS):
        b_mean = X_benign_scaled[:, i].mean()
        b_std = X_benign_scaled[:, i].std()
        a_mean = X_attack_scaled[:, i].mean()
        a_std = X_attack_scaled[:, i].std()
        print(
            f"{name:<32} "
            f"{b_mean:+7.3f} ± {b_std:6.3f}       "
            f"{a_mean:+7.3f} ± {a_std:6.3f}"
        )

    print(f"\nSaving fitted pipeline to {PIPELINE_PATH}...")
    pipeline.to_file(PIPELINE_PATH)
    size_kb = PIPELINE_PATH.stat().st_size / 1024
    print(f"  Wrote {size_kb:.1f} KB.")

    print("\nRound-trip test: loading pipeline back from disk...")
    reloaded = FeaturePipeline.from_file(PIPELINE_PATH)
    X_reloaded = reloaded.transform(benign)
    if np.allclose(X_benign_scaled, X_reloaded):
        print("  Round-trip identical. Pipeline persists correctly.")
    else:
        print("  MISMATCH — persisted pipeline behaves differently. Investigate.")


if __name__ == "__main__":
    main()
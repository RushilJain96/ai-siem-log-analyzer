"""Sample CICIDS 2017 CSVs into a single working file.

Reads the eight raw CICIDS 2017 CSVs from the directory specified by the
CICIDS_DIR environment variable (default: ~/Downloads/MachineLearningCSV/
MachineLearningCVE), takes a 2% random sample from each using chunked
reading, normalizes column names, and writes the concatenated result to
data/raw/cicids_sample.csv.

Run once from the project root:
    python scripts/sample_cicids.py

Output size: ~55,000 rows, ~30 MB. The output is gitignored (data/raw/*)
so it isn't committed. Each developer runs this script once against their
local copy of the raw dataset.

Design notes:
- Chunked reading (100K rows/chunk) keeps peak memory ~100 MB regardless
  of raw file size. Larger chunks are faster but consume more memory.
- Sampling per-chunk (rather than after concatenation) preserves the
  memory bound. It's mathematically equivalent to sampling the full file
  when the sample fraction is small.
- random_state=42 makes the sample deterministic. Same script + same
  raw data = same output. Reproducibility for downstream experiments.
"""
import os
from pathlib import Path

import pandas as pd


SAMPLE_FRACTION = 0.02
CHUNK_SIZE = 100_000
RANDOM_SEED = 42

DEFAULT_CICIDS_DIR = Path.home() / "Downloads" / "MachineLearningCSV" / "MachineLearningCVE"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = PROJECT_ROOT / "data" / "raw" / "cicids_sample.csv"


def sample_one_file(path: Path) -> pd.DataFrame:
    """Return a 2% random sample from one CICIDS CSV, chunk by chunk."""
    sampled_chunks = []
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE):
        chunk.columns = chunk.columns.str.strip()
        sampled = chunk.sample(frac=SAMPLE_FRACTION, random_state=RANDOM_SEED)
        sampled_chunks.append(sampled)
    return pd.concat(sampled_chunks, ignore_index=True)


def main() -> None:
    cicids_dir = Path(os.getenv("CICIDS_DIR", DEFAULT_CICIDS_DIR))
    if not cicids_dir.is_dir():
        raise SystemExit(
            f"CICIDS directory not found: {cicids_dir}\n"
            f"Set CICIDS_DIR env var to override the default location."
        )

    csv_files = sorted(cicids_dir.glob("*.csv"))
    if not csv_files:
        raise SystemExit(f"No CSVs found in {cicids_dir}")

    print(f"Found {len(csv_files)} CSV files in {cicids_dir}")

    all_samples = []
    for i, path in enumerate(csv_files, start=1):
        print(f"[{i}/{len(csv_files)}] Sampling {path.name}...")
        sampled = sample_one_file(path)
        print(f"  -> kept {len(sampled)} rows")
        all_samples.append(sampled)

    combined = pd.concat(all_samples, ignore_index=True)
    print(f"\nTotal sample size: {len(combined)} rows, {len(combined.columns)} columns")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_PATH, index=False)
    print(f"\nWrote sample to {OUTPUT_PATH}")

    print(f"\nLabel distribution in sample:")
    print(combined["Label"].value_counts())


if __name__ == "__main__":
    main()
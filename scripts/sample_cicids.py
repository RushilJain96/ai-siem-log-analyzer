"""Sample CICIDS 2017 CSVs into a single working file.

Reads the eight raw CICIDS 2017 CSVs from the directory specified by the
CICIDS_DIR environment variable (default: ~/Downloads/MachineLearningCSV/
MachineLearningCVE), samples each using chunked reading, normalizes
column names, and writes the concatenated result to
data/raw/cicids_sample.csv.

Run once from the project root:
    python scripts/sample_cicids.py

Output size: ~58,000 rows (up from ~55,000 before the class-aware floor
below), ~30 MB. The output is gitignored (data/raw/*) so it isn't
committed. Each developer runs this script once against their local
copy of the raw dataset.

Design notes:

1. Class-aware sampling, not flat 2% for every row (a prior version of
   this script sampled every row at a flat SAMPLE_FRACTION regardless
   of label and called it "stratified" in the docs -- it wasn't; that
   was a documentation bug, not a design choice). BENIGN rows are
   sampled at SAMPLE_FRACTION: there's plenty of benign data, and
   model.detector.Detector.fit() only ever trains on a benign subset,
   so benign volume isn't the constraint. Non-BENIGN (attack) rows are
   sampled at whichever is larger: SAMPLE_FRACTION, or the fraction
   needed to reach MIN_ATTACK_SAMPLE_SIZE rows for that label across
   the whole file (capped at 1.0, i.e. keep everything, for labels
   whose total population is smaller than the floor). Attack rows are
   eval-only in Day 4's train/test split -- fit() never sees them --
   so oversampling them costs nothing at training time. It only makes
   per-attack-type recall estimates trustworthy instead of statistical
   noise, and stops rows from extremely rare classes (Heartbleed,
   Infiltration, SQL Injection in the full CICIDS-2017 dataset each
   have well under 50 total rows) from vanishing entirely at 2%.

2. MIN_ATTACK_SAMPLE_SIZE = 300: a rough floor for "not statistical
   noise." At n=300, a worst-case (p=0.5) binomial proportion estimate
   has a 95% CI margin of error of about ±5.7 percentage points --
   not tight, but a different world from n=1 or n=13, where a single
   flipped prediction swings the reported recall by double digits.

3. Two passes per file, both chunked to keep peak memory bounded
   regardless of file size:
     pass 1 (_count_labels): tally rows per label across the WHOLE
       file, reading only the Label column.
     pass 2 (sample_one_file): re-read chunk by chunk, sampling each
       label's rows within a chunk using the FILE-WIDE fraction from
       pass 1 -- not a fraction computed from that chunk alone. This
       is what makes the floor accurate regardless of how a label's
       rows happen to fall across chunk boundaries. A single-pass,
       chunk-local floor would have applied the floor once per chunk
       a label appears in, silently over-sampling any class split
       across multiple chunks.

4. random_state=42 makes the sample deterministic. Same script + same
   raw data = same output. Reproducibility for downstream experiments.

5. CICIDS CSVs have inconsistent leading whitespace in column names
   (a known quirk -- see model/parser.py). _find_raw_label_column()
   resolves the actual on-disk spelling once per file so pass 1 can
   request only that column via usecols, instead of reading every
   column just to find the label.
"""
import os
from pathlib import Path

import pandas as pd


LABEL_COL = "Label"
SAMPLE_FRACTION = 0.02
MIN_ATTACK_SAMPLE_SIZE = 300
CHUNK_SIZE = 100_000
RANDOM_SEED = 42

DEFAULT_CICIDS_DIR = Path.home() / "Downloads" / "MachineLearningCSV" / "MachineLearningCVE"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = PROJECT_ROOT / "data" / "raw" / "cicids_sample.csv"


def _find_raw_label_column(path: Path) -> str:
    """Resolve the on-disk spelling of the Label column (may have
    leading whitespace) by peeking at just the header row."""
    header = pd.read_csv(path, nrows=0).columns
    for col in header:
        if col.strip() == LABEL_COL:
            return col
    raise ValueError(f"No Label column found in {path}")


def _count_labels(path: Path, raw_label_col: str) -> dict[str, int]:
    """First pass: total rows per label across the whole file."""
    counts: dict[str, int] = {}
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, usecols=[raw_label_col]):
        chunk_counts = chunk[raw_label_col].str.strip().value_counts()
        for label, count in chunk_counts.items():
            counts[label] = counts.get(label, 0) + int(count)
    return counts


def _sample_fraction_for_label(label: str, total_count: int) -> float:
    if label == "BENIGN":
        return SAMPLE_FRACTION
    return max(SAMPLE_FRACTION, min(1.0, MIN_ATTACK_SAMPLE_SIZE / total_count))


def sample_one_file(path: Path) -> pd.DataFrame:
    """Return a class-aware sample from one CICIDS CSV (see design
    notes 1 and 3 above)."""
    raw_label_col = _find_raw_label_column(path)
    label_counts = _count_labels(path, raw_label_col)
    fractions = {
        label: _sample_fraction_for_label(label, count)
        for label, count in label_counts.items()
    }

    sampled_chunks = []
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE):
        chunk.columns = chunk.columns.str.strip()
        labels = chunk[LABEL_COL].str.strip()
        for label, group in chunk.groupby(labels):
            sampled_chunks.append(
                group.sample(frac=fractions[label], random_state=RANDOM_SEED)
            )
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

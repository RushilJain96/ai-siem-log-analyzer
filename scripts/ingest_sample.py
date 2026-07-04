"""Ingest sampled CICIDS rows into the running SIEM API.

Reads data/raw/cicids_sample.csv (produced by sample_cicids.py), parses
each row via model.parser, and POSTs to /logs/ingest via httpx. Requires
a locally running uvicorn instance (default: http://127.0.0.1:8000).

Usage:
    # In terminal 1:
    uvicorn api.main:app

    # In terminal 2:
    python scripts/ingest_sample.py                # 5000 rows (default)
    python scripts/ingest_sample.py --count 10000  # more
    python scripts/ingest_sample.py --count 0      # all rows in the sample

Prints a progress line every 500 rows and a final summary with success
count, failure count, and elapsed time.
"""
import argparse
import time
from pathlib import Path

import httpx
import pandas as pd

from model.parser import parse_cicids_row


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PATH = PROJECT_ROOT / "data" / "raw" / "cicids_sample.csv"

DEFAULT_URL = "http://127.0.0.1:8000"
DEFAULT_COUNT = 5000
PROGRESS_EVERY = 500


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
        help=f"Number of rows to ingest. 0 means all. Default: {DEFAULT_COUNT}",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Base URL of the running API. Default: {DEFAULT_URL}",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for shuffling. Default: 42",
    )
    return parser.parse_args()


def _serialize_for_json(payload: dict) -> dict:
    """httpx's json= parameter needs JSON-native types.

    Our parser returns event_time as a Python datetime; JSON doesn't have
    a native datetime type, so we ISO-serialize it here.
    """
    return {
        **payload,
        "event_time": payload["event_time"].isoformat(),
    }


def main() -> None:
    args = parse_args()

    if not SAMPLE_PATH.exists():
        raise SystemExit(
            f"Sample not found at {SAMPLE_PATH}\n"
            f"Run scripts/sample_cicids.py first."
        )

    print(f"Loading sample from {SAMPLE_PATH.name}...")
    df = pd.read_csv(SAMPLE_PATH)
    print(f"  Loaded {len(df)} rows.")

    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    if args.count > 0:
        df = df.head(args.count)
    total = len(df)
    print(f"Ingesting {total} rows to {args.url}/logs/ingest...")

    ingest_url = f"{args.url}/logs/ingest"
    success = 0
    failed = 0
    start = time.perf_counter()

    with httpx.Client(timeout=10.0) as client:
        for i, row in enumerate(df.to_dict(orient="records"), start=1):
            payload = _serialize_for_json(parse_cicids_row(row))
            try:
                response = client.post(ingest_url, json=payload)
                if response.status_code == 201:
                    success += 1
                else:
                    failed += 1
                    if failed <= 5:
                        print(f"  Row {i}: HTTP {response.status_code}: {response.text[:200]}")
            except httpx.HTTPError as e:
                failed += 1
                if failed <= 5:
                    print(f"  Row {i}: {type(e).__name__}: {e}")

            if i % PROGRESS_EVERY == 0:
                elapsed = time.perf_counter() - start
                rate = i / elapsed
                print(f"  [{i}/{total}] {rate:.0f} rows/s")

    elapsed = time.perf_counter() - start
    print(f"\nDone in {elapsed:.1f}s ({total / elapsed:.0f} rows/s)")
    print(f"  Success: {success}")
    print(f"  Failed:  {failed}")


if __name__ == "__main__":
    main()
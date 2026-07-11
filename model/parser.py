"""Parse CICIDS 2017 flow rows into our ingest schema.

The CICIDS ML CSVs contain 78 numerical features per flow plus one Label
column. Our schema stores a small structured subset, the 18 flow-shape
features the detector consumes, and the raw row JSON-serialized for
forensic replay. This module owns that translation.

Known limitations:
- The ML-ready CICIDS CSVs have IPs stripped for privacy, so source_ip
  and destination_ip are always None. In production we would ingest
  from the GeneratedLabelledFlows version or from raw PCAPs.
- Timestamps are set to the current wall-clock time at parse. The ML
  CSVs don't include per-flow timestamps.
- Flow rate columns (Flow Bytes/s, Flow Packets/s) can be inf when
  duration is zero. These are converted to None on output.
"""
import json
import math
from datetime import datetime, timezone
from typing import Any

from model.features import FEATURE_COLUMNS


# Column names the parser reads. Whitespace is expected to already be
# stripped by the caller (the sampler does this before writing the CSV).
_LABEL_COL = "Label"
_DURATION_COL = "Flow Duration"
_FWD_BYTES_COL = "Total Length of Fwd Packets"
_BWD_BYTES_COL = "Total Length of Bwd Packets"


def _to_finite_int(value: Any) -> int | None:
    """Coerce a numeric value to a native int, or None if not finite.

    inf, -inf, and NaN all return None so they can be stored as SQL NULL.
    """
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        return None
    return int(f)


def _to_finite_float(value: Any) -> float | None:
    """Coerce a numeric value to a native float, or None if not finite."""
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        return None
    return f


def _extract_features(row: dict[str, Any]) -> dict[str, float]:
    """Pull the 18 model-feature columns out of a raw CICIDS row.

    A column that's missing from the row, or holds inf/NaN, is OMITTED
    from the result entirely rather than set to None. AnomalyScorer.score()
    (Day 5) already treats a missing dict key as "impute this from the
    fitted medians" -- there's no need for a separate representation of
    "present but invalid" vs. "absent"; they mean the same thing to the
    scorer, so we don't invent one.
    """
    features = {}
    for col in FEATURE_COLUMNS:
        value = _to_finite_float(row.get(col))
        if value is not None:
            features[col] = value
    return features


def parse_cicids_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert one CICIDS 2017 flow row into ingest-schema keyword arguments.

    Args:
        row: A mapping representing one row of a CICIDS CSV. Column names
            must have whitespace already stripped (the sampler does this
            before writing to disk).

    Returns:
        A dict matching api.routes.logs.LogIngest's fields (this is what
        scripts/ingest_sample.py POSTs as the request body). Fields not
        derivable from CICIDS (IPs, protocol, per-flow timestamp) are set
        to None. is_alert and anomaly_score are NOT included -- the
        server computes those from `features` (Day 5); this module has
        no opinion on them, even though CICIDS's ground-truth Label
        would make that tempting.
    """
    label = str(row.get(_LABEL_COL, "")).strip()

    duration_micros = _to_finite_int(row.get(_DURATION_COL))
    duration_seconds = duration_micros / 1_000_000 if duration_micros is not None else None

    fwd_bytes = _to_finite_int(row.get(_FWD_BYTES_COL)) or 0
    bwd_bytes = _to_finite_int(row.get(_BWD_BYTES_COL)) or 0
    bytes_transferred = fwd_bytes + bwd_bytes

    return {
        "event_time": datetime.now(timezone.utc),
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "event_type": label or None,
        "bytes_transferred": bytes_transferred,
        "duration_seconds": duration_seconds,
        "flag": None,
        "raw_payload": json.dumps(_json_safe(row)),
        "features": _extract_features(row),
    }


def _json_safe(row: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of row with non-finite floats replaced by None.

    json.dumps() rejects inf and NaN by default (they're not valid JSON).
    We convert them to None so the raw payload is round-trippable.
    """
    safe = {}
    for key, value in row.items():
        if isinstance(value, float) and not math.isfinite(value):
            safe[key] = None
        else:
            safe[key] = value
    return safe
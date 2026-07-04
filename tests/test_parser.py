"""Unit tests for model/parser.py.

Each test constructs a small dict representing a CICIDS row (or a
deliberately broken one) and verifies the parser produces the expected
LogEntry kwargs. Tests are isolated — no filesystem, no database, no
HTTP. Fast.
"""
import json
import math
from datetime import datetime, timezone

from model.parser import parse_cicids_row


def _make_row(**overrides) -> dict:
    """Build a well-formed CICIDS row dict for use as a test baseline.

    Individual tests override specific fields via keyword arguments to
    exercise different code paths without redefining every field.
    """
    baseline = {
        "Label": "BENIGN",
        "Flow Duration": 1_000_000,  # 1 second in microseconds
        "Total Length of Fwd Packets": 500,
        "Total Length of Bwd Packets": 300,
        "Destination Port": 80,
    }
    baseline.update(overrides)
    return baseline


def test_benign_row_is_not_alert():
    parsed = parse_cicids_row(_make_row(Label="BENIGN"))
    assert parsed["is_alert"] is False
    assert parsed["event_type"] == "BENIGN"


def test_attack_row_is_alert():
    parsed = parse_cicids_row(_make_row(Label="DoS Hulk"))
    assert parsed["is_alert"] is True
    assert parsed["event_type"] == "DoS Hulk"


def test_label_whitespace_is_stripped():
    parsed = parse_cicids_row(_make_row(Label="  BENIGN  "))
    assert parsed["event_type"] == "BENIGN"
    assert parsed["is_alert"] is False


def test_empty_label_is_not_alert():
    parsed = parse_cicids_row(_make_row(Label=""))
    assert parsed["is_alert"] is False
    assert parsed["event_type"] is None


def test_duration_converts_microseconds_to_seconds():
    parsed = parse_cicids_row(_make_row(**{"Flow Duration": 2_500_000}))
    assert parsed["duration_seconds"] == 2.5


def test_bytes_are_summed_from_fwd_and_bwd():
    parsed = parse_cicids_row(_make_row(**{
        "Total Length of Fwd Packets": 1000,
        "Total Length of Bwd Packets": 700,
    }))
    assert parsed["bytes_transferred"] == 1700


def test_missing_bytes_treated_as_zero():
    row = _make_row()
    del row["Total Length of Bwd Packets"]
    parsed = parse_cicids_row(row)
    assert parsed["bytes_transferred"] == 500


def test_inf_duration_becomes_none():
    parsed = parse_cicids_row(_make_row(**{"Flow Duration": math.inf}))
    assert parsed["duration_seconds"] is None


def test_nan_duration_becomes_none():
    parsed = parse_cicids_row(_make_row(**{"Flow Duration": math.nan}))
    assert parsed["duration_seconds"] is None


def test_missing_ip_fields_are_none():
    parsed = parse_cicids_row(_make_row())
    assert parsed["source_ip"] is None
    assert parsed["destination_ip"] is None
    assert parsed["protocol"] is None
    assert parsed["flag"] is None


def test_anomaly_score_is_none_at_parse_time():
    parsed = parse_cicids_row(_make_row(Label="DoS Hulk"))
    assert parsed["anomaly_score"] is None


def test_event_time_is_recent_utc_datetime():
    before = datetime.now(timezone.utc)
    parsed = parse_cicids_row(_make_row())
    after = datetime.now(timezone.utc)

    assert isinstance(parsed["event_time"], datetime)
    assert parsed["event_time"].tzinfo is not None
    assert before <= parsed["event_time"] <= after


def test_raw_payload_is_valid_json():
    parsed = parse_cicids_row(_make_row())
    decoded = json.loads(parsed["raw_payload"])
    assert decoded["Label"] == "BENIGN"
    assert decoded["Flow Duration"] == 1_000_000


def test_raw_payload_handles_inf_by_nulling():
    """json.dumps rejects inf/NaN; the parser must sanitize before dumping."""
    parsed = parse_cicids_row(_make_row(**{"Flow Bytes/s": math.inf}))
    decoded = json.loads(parsed["raw_payload"])
    assert decoded["Flow Bytes/s"] is None
"""Unit tests for model/severity.py.

Pure-function tests over hand-picked scores, with particular attention
to the exact tier boundaries -- off-by-one on an inclusive/exclusive
cutoff is the classic bucketing bug, so every cutoff value is asserted
explicitly.
"""
import pytest

from model.severity import (
    CRITICAL,
    CRITICAL_MIN,
    HIGH,
    HIGH_MIN,
    LOW,
    MEDIUM,
    MEDIUM_MIN,
    score_bounds_for,
    severity_for,
)


# --- non-alerts always get None -----------------------------------------


def test_non_alert_is_none_even_with_high_score():
    assert severity_for(0.99, is_alert=False) is None


def test_alert_with_none_score_is_none():
    assert severity_for(None, is_alert=True) is None


def test_non_alert_with_none_score_is_none():
    assert severity_for(None, is_alert=False) is None


# --- tier mapping for representative scores ------------------------------


def test_low_tier():
    assert severity_for(0.10, is_alert=True) == LOW


def test_medium_tier():
    assert severity_for(0.35, is_alert=True) == MEDIUM


def test_high_tier():
    assert severity_for(0.60, is_alert=True) == HIGH


def test_critical_tier():
    assert severity_for(0.90, is_alert=True) == CRITICAL


# --- exact boundary values (lower-inclusive) ----------------------------


def test_score_just_above_zero_is_low():
    assert severity_for(0.0001, is_alert=True) == LOW


def test_medium_min_boundary_is_medium():
    assert severity_for(MEDIUM_MIN, is_alert=True) == MEDIUM


def test_just_below_medium_min_is_low():
    assert severity_for(MEDIUM_MIN - 0.0001, is_alert=True) == LOW


def test_high_min_boundary_is_high():
    assert severity_for(HIGH_MIN, is_alert=True) == HIGH


def test_just_below_high_min_is_medium():
    assert severity_for(HIGH_MIN - 0.0001, is_alert=True) == MEDIUM


def test_critical_min_boundary_is_critical():
    assert severity_for(CRITICAL_MIN, is_alert=True) == CRITICAL


def test_just_below_critical_min_is_high():
    assert severity_for(CRITICAL_MIN - 0.0001, is_alert=True) == HIGH


def test_score_of_one_is_critical():
    assert severity_for(1.0, is_alert=True) == CRITICAL


# --- score_bounds_for() -------------------------------------------------


def test_bounds_are_contiguous_and_cover_full_range():
    """Each tier's upper bound must equal the next tier's lower bound,
    with no gap or overlap, spanning [0.0, 1.0]."""
    low_lo, low_hi = score_bounds_for(LOW)
    med_lo, med_hi = score_bounds_for(MEDIUM)
    high_lo, high_hi = score_bounds_for(HIGH)
    crit_lo, crit_hi = score_bounds_for(CRITICAL)

    assert low_lo == 0.0
    assert low_hi == med_lo
    assert med_hi == high_lo
    assert high_hi == crit_lo
    assert crit_hi == 1.0


def test_bounds_match_severity_for_at_midpoints():
    """A score at the midpoint of each tier's bounds should map back to
    that same tier via severity_for -- proves the two functions agree."""
    for tier in (LOW, MEDIUM, HIGH, CRITICAL):
        lo, hi = score_bounds_for(tier)
        midpoint = (lo + hi) / 2
        assert severity_for(midpoint, is_alert=True) == tier


def test_bounds_unknown_severity_raises():
    with pytest.raises(ValueError, match="Unknown severity"):
        score_bounds_for("catastrophic")
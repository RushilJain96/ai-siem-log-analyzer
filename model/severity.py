"""Severity tiers derived from a detector anomaly score (Day 6).

Turns the continuous anomaly_score (a float in (0, 1) from
Detector.anomaly_score(), higher = more anomalous) into a small,
triage-friendly label an analyst can rank against. A raw 0.064 vs 0.97
tells a human nothing at a glance; "low" vs "critical" does.

Design decisions:

1. Severity is defined ONLY for alerts (is_alert=True). A log that
   never crossed the detector's decision_threshold isn't a "low
   severity alert" -- it isn't an alert at all, so its severity is
   None. This is what keeps false positives from being alarming: a
   benign flow that just barely tripped the threshold lands in "low",
   visibly the least urgent thing on the board, while non-alerts carry
   no severity label whatsoever.

2. Four tiers with round, explainable cutoffs. HIGH begins at 0.50 --
   the sigmoid's own calibrated inlier/outlier boundary from Day 4
   (anomaly_score = 0.5 means "the model's own decision boundary"), so
   that one cutoff is principled rather than arbitrary; the others
   (0.25, 0.75) are evenly spaced round numbers chosen for
   explainability over statistical optimality. Percentile-based
   cutoffs were considered and rejected: for this project, "here is
   exactly why each boundary sits where it does" is worth more than a
   tuned number nobody can justify in an interview.

3. Computed, never stored. severity is a pure function of
   anomaly_score -- deriving it on read (in the API response, and as a
   score-range WHERE clause for filtering) means the cutoffs live in
   exactly ONE place. If a cutoff ever changes, no historical row goes
   stale and no migration is needed. Storing it would create a second
   source of truth that could silently drift from the score it's meant
   to reflect -- the same reasoning behind not letting clients set
   is_alert.

Because severity maps directly back to score ranges, filtering by
severity is still an efficient, indexable SQL query (see
score_bounds_for()); we get clean derivation AND fast filtering, no
trade-off.
"""
from __future__ import annotations

# Tier names, ordered least -> most urgent.
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

SEVERITIES = (LOW, MEDIUM, HIGH, CRITICAL)

# Lower-inclusive cutoffs on anomaly_score. A score in [cutoff, next)
# maps to that tier. The bottom of "low" is implicitly the detector's
# decision_threshold: anything below that isn't an alert and never
# reaches this module.
MEDIUM_MIN = 0.25
HIGH_MIN = 0.50   # the model's own calibrated decision boundary (Day 4)
CRITICAL_MIN = 0.75


def severity_for(anomaly_score: float | None, is_alert: bool) -> str | None:
    """Map an anomaly score to a severity tier, or None if not an alert.

    Args:
        anomaly_score: the detector's score in (0, 1), or None if the
            entry was never scored (no model loaded / no features).
        is_alert: whether the entry was flagged. Non-alerts always get
            None regardless of score.

    Returns:
        One of "low"/"medium"/"high"/"critical", or None when the entry
        is not an alert (or has no score to tier).
    """
    if not is_alert or anomaly_score is None:
        return None
    if anomaly_score >= CRITICAL_MIN:
        return CRITICAL
    if anomaly_score >= HIGH_MIN:
        return HIGH
    if anomaly_score >= MEDIUM_MIN:
        return MEDIUM
    return LOW


def score_bounds_for(severity: str) -> tuple[float, float]:
    """Return the [lower, upper) anomaly_score bounds for a tier.

    Used by the CRUD layer to translate a `severity=high` filter into
    an indexable `anomaly_score >= lower AND anomaly_score < upper`
    WHERE clause, instead of computing severity per-row in Python.

    The upper bound of "critical" is 1.0 exclusive; anomaly_score is a
    sigmoid output that asymptotically approaches but never reaches 1.0,
    so no real score is excluded by that. (A hypothetical exact 1.0
    would fall outside -- an acceptable, effectively-impossible edge.)

    Raises:
        ValueError: if `severity` is not one of the known tiers.
    """
    bounds = {
        LOW: (0.0, MEDIUM_MIN),
        MEDIUM: (MEDIUM_MIN, HIGH_MIN),
        HIGH: (HIGH_MIN, CRITICAL_MIN),
        CRITICAL: (CRITICAL_MIN, 1.0),
    }
    if severity not in bounds:
        raise ValueError(
            f"Unknown severity {severity!r}; expected one of {SEVERITIES}."
        )
    return bounds[severity]
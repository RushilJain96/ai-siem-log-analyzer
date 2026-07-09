# Day 4 model evaluation — full writeup

Linked from the README's [Model evaluation](../README.md#model-evaluation)
summary. This is the detailed methodology, numbers, and reasoning behind
that summary.

## `contamination` correction

The original project doc specified `contamination=0.1`. The actual value
used is `contamination=0.01` — `contamination` is sklearn's prior on how
much of the *fit* data is already anomalous, not an estimate of
real-world attack prevalence. `Detector.fit()` trains on benign-only
rows, so the only expected contamination is label noise (CICIDS
mislabeling), not the ~19.6% attack prevalence seen in the full
CICIDS-2017 dataset. Conflating "how noisy is my training set" with "how
common are attacks in production" is an easy mistake with an anomaly
detector like this one.

## Why the exact contamination value barely matters here

sklearn's `IsolationForest` uses `contamination` for exactly one thing
after fitting: setting `offset_`, a constant subtracted from every row's
raw isolation score to produce `decision_function()`. It does **not**
affect how the trees are built, so `score_samples()` — and therefore the
ranking of every row from most- to least-anomalous — is identical no
matter what `contamination` is set to.

`Detector.anomaly_score()` is a strictly monotonic transform of
`decision_function()`, and `scripts/train_detector.py` tunes
`decision_threshold` from an ROC curve, which depends only on that
ranking, not on absolute score values. Net effect: raising or lowering
`contamination` changes the printed sanity-check self-flag rate and the
raw numeric value of the tuned threshold, but the actual precision/
recall/FPR achieved at the chosen operating point comes out the same.

The real levers for trading recall against FPR are `FPR_BUDGET` in
`scripts/train_detector.py` (moves along the *same* ROC curve) and the
feature set itself (changes what the ROC curve looks like in the first
place) — not `contamination`.

## Measured operating points

An early exploration (before the sampler fix below, on a flat-2% sample:
9,107 benign_test + 11,083 attack_test) compared three threshold
strategies to choose an operating point:

| Threshold strategy | Recall | FPR | Precision |
|---|---|---|---|
| `contamination`-default | 0.276 | 0.011 | 0.969 |
| F1-maximizing | 0.954 | 0.473 | 0.710 |
| FPR ≤ 5% budget | 0.351 | 0.050 | 0.895 |

The F1-maximizing threshold is not usable — a 47% false-positive rate
means analysts drown in noise (the textbook alert-fatigue failure mode).
The FPR-budget strategy was chosen as the operating point going forward.

**Current operating point** (after the sampler fix, on 9,093
benign_test + 12,827 attack_test, `decision_threshold` ≈ 0.0211):

recall **0.3491**, FPR **0.0498**, precision **0.9081**, adjusted
precision **0.6308**. TP=4478, TN=8640, FP=453, FN=8349.

Aggregate recall/precision/FPR barely moved from the pre-fix numbers
above — expected, since neither training data nor the model changed,
only the evaluation set's class balance did.

## Why aren't all attacks detected?

Per-attack-type recall at the current operating point splits cleanly
into two groups:

| Attack type | Rows | Recall |
|---|---|---|
| Heartbleed | 11 (small sample) | 100.0% |
| Infiltration | 36 | 80.6% |
| DoS Hulk | 4,620 | 67.6% |
| DDoS | 2,561 | 41.5% |
| DoS GoldenEye | 300 | 27.0% |
| DoS Slowhttptest | 300 | 26.3% |
| DoS slowloris | 300 | 22.3% |
| Bot | 300 | 3.0% |
| Web Attack XSS | 300 | 1.7% |
| Web Attack Brute Force | 300 | 1.0% |
| PortScan | 3,179 | 0.2% |
| SSH-Patator | 299 | 0.0% |
| FTP-Patator | 300 | 0.0% |
| Web Attack SQL Injection | 21 (small sample) | 0.0% |

**Structurally invisible (0–3% recall): FTP-/SSH-Patator, PortScan, Web
Attack SQLi/XSS/Brute Force, Bot.** These attacks' "attack-ness" isn't in
any single flow's shape. Credential brute-forcing and port scanning are
collective anomalies — the signal is repetition (many similar connection
attempts from one source in a short window), which needs a per-source,
cross-flow feature the current 18 features don't include, and which this
CICIDS variant can't support anyway since source IPs are stripped (see
the README's [Known limitations](../README.md#known-limitations)). Web
attacks (SQLi/XSS/Brute Force) are payload-content attacks riding over
flows that look statistically
identical to legitimate HTTP traffic — flow metadata alone has no
visibility into packet contents. No amount of threshold or
`contamination` tuning fixes either of these; it needs different
features (e.g. connection-rate-per-source) or a different detection
layer entirely (payload inspection / WAF-style signatures for the web
attacks).

**Partially detected (22–68% recall): the DoS/DDoS family, plus
Infiltration.** These genuinely do shift flow-shape statistics (Day 3's
discrimination analysis confirmed this), so the detector can see them in
principle. Two things cap recall below 100%: (1) `decision_threshold` is
deliberately conservative — tuned to a 5% FPR budget, not to maximize
recall, so only the most extreme instances clear the bar (the
F1-maximizing threshold above reached 95% recall, at an unusable FPR);
(2) the recall ordering — Hulk 67.6% > DDoS 41.5% > GoldenEye 27.0% ≈
Slowhttptest 26.3% > slowloris 22.3% — tracks almost exactly how "loud"
each technique is by design. Hulk is a full-throttle flood; slowloris is
deliberately built to trickle requests and mimic legitimate slow
connections, evading exactly the kind of volumetric signature this
feature set looks for.

Infiltration's surprisingly strong 80.6% recall (n=36 — small enough to
treat with some caution) suggests infiltration flows in this dataset
have unusually distinctive duration/rate characteristics. Worth a closer
look in a future day, but not investigated yet.

**Measurement caveat, for honesty:** individual per-type numbers carry
real run-to-run variance from resampling — a different random draw pulls
different specific flows each time, on top of small shifts in the tuned
threshold between runs. DDoS moved from 24.0% to 41.5% recall across two
sampler runs on a nearly unchanged row count (2,500 → 2,561) — too large
a swing to be pure sampling luck at that n, so treat any single
per-type number as directionally informative, not exact, until checked
against more than one sampled draw.

## The sampler fix (Day 4)

`scripts/sample_cicids.py` originally sampled every row at a flat 2%
regardless of label, while its docs called this "stratified" — it
wasn't; that was a documentation bug, not a design choice. At a flat 2%,
CICIDS's rarest attack classes (Heartbleed ≈11 total rows, Infiltration
≈36, SQL Injection ≈21 in the full dataset) either vanished from the
eval set entirely or survived on 1-2 rows — statistical noise, and in
Infiltration's case, an entire attack category invisible to evaluation
with no indication anything was missing.

The fix: BENIGN rows still sample at a flat 2% (there's plenty of benign
data, and `Detector.fit()` only ever trains on benign rows, so volume
isn't the constraint there). Attack rows sample at `max(2%, 300 /
total_count)`, capped at 100% — so classes smaller than 300 total rows
are kept in full, and moderately-rare classes get boosted toward 300
instead of being crushed at 2%. Total dataset size grew from ~56.6K to
~58.3K rows (about +3%) — a small cost for eliminating an entire class
of blind, untrustworthy measurements.

Confirmed this did not change the model (as expected — attack row volume
has zero effect on a benign-only `fit()`): aggregate recall/precision/
FPR moved by roughly a percentage point either way between the pre- and
post-fix runs, consistent with re-weighting evaluation rows rather than
retraining anything.

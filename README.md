# AI-Driven SIEM Log Analyzer

> A cybersecurity tool that ingests network logs, detects anomalies via Isolation Forest, and surfaces high-risk alerts through a REST API. Built to understand how production SIEM tools (Splunk, Wazuh, Cortex XDR) work under the hood.

[![CI](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml)

## Status — Day 6 of 10

This project is being built incrementally. The current state covers the **foundation** (HTTP API, database, structured logging, CI), the **ML pipeline core** (feature engineering, anomaly detection, evaluation), **live detection wired into the API**, and **alert triage** (severity tiers and filtering). The dashboard is still upcoming.

**Working today:**
- FastAPI service with auto-generated OpenAPI docs at `/docs`
- SQLite persistence layer using SQLAlchemy 2.0
- Endpoints: `POST /logs/ingest`, `GET /logs` (with filters), `GET /logs/alerts`, `GET /stats`, `GET /health`
- Structured JSON logging configured via environment variables
- pytest test suite covering ingest → list → stats, parser, feature pipeline, detector, live inference, end-to-end detection, severity, and alert-filtering tests (126 tests total)
- GitHub Actions CI running tests on every push
- Chunked sampler producing a class-aware sample from the eight CICIDS 2017 CSVs: benign rows at a flat 2%, attack rows at 2% or a 300-row-per-class floor (whichever is larger) — a Day 4 fix, since a flat 2% was silently reducing rare attack classes (Heartbleed, Infiltration) to statistical noise or zero rows
- CICIDS row parser handling the dataset's known quirks (leading whitespace in column names, `inf`/`NaN` in flow-rate columns, missing IPs)
- HTTP-driven ingestion pipeline that seeds the database from parsed CICIDS rows
- Feature engineering pipeline: 18 hand-selected flow-shape features — timing/rate, directional packet-size statistics, TCP flag counts (SYN/ACK/RST/PSH), TCP window sizes, and down/up ratio
- StandardScaler-based normalization fitted on benign rows only to prevent training-time data leakage
- Fitted preprocessing pipeline persisted to disk via `joblib` for reuse at inference time
- Per-feature discrimination analysis run at fit time — attack rows shift up to +3.46 std devs on backward packet-length features (Bwd Packet Length Std), confirming directional stats outperform aggregate stats
- `Detector`: an Isolation Forest wrapper with calibrated `anomaly_score()` (sigmoid over `decision_function()`, scale calibrated from the training data's own spread — see [Model evaluation](#model-evaluation)), a persisted operational `decision_threshold` decoupled from training-time `contamination`, and a static `evaluate()` for precision/recall/F1/FPR plus prevalence-adjusted precision
- `scripts/train_detector.py`: fits on an 80% benign split (all attack rows held out for evaluation only), tunes `decision_threshold` by maximizing recall subject to an FPR budget
- Per-attack-type recall breakdown across all 14 CICIDS attack labels, explaining exactly which attacks the detector can and can't see and why (see [Model evaluation](#model-evaluation))
- `POST /logs/ingest` now runs every entry through the trained detector: `AnomalyScorer` (`model/inference.py`) composes `FeaturePipeline` + `Detector` into one scoring call, loaded once at app startup and injected via FastAPI's dependency system — same pattern as the DB session, not reloaded per-request
- Closed a real trust-boundary gap: `is_alert`/`anomaly_score` can no longer be set by the client. `LogIngest` now rejects them outright (`extra="forbid"` → a loud 422, not a silently dropped field) instead of trusting caller-supplied labels
- `features: dict[str, float]` replaces the old ground-truth-label shortcut. A partial or empty features dict degrades gracefully via median imputation (reusing Day 3's logic, built for exactly this case); a missing trained model degrades gracefully too — the API still starts and ingests, just skips scoring and logs a warning
- Severity tiers (`low`/`medium`/`high`/`critical`) derived from `anomaly_score` in `model/severity.py` — computed on read, never stored (one source of truth for the cutoffs), and `null` for non-alerts. The `high` cutoff (0.5) is anchored to the model's own calibrated decision boundary from Day 4
- `GET /logs` gains composable filters — `is_alert`, `severity`, and a `start_time`/`end_time` window — plus a dedicated `GET /logs/alerts` view ordered most-anomalous-first for triage (a convenience shortcut for the common `?is_alert=true` case)
- `/stats` gains a per-severity alert breakdown (`alerts_by_severity`) for at-a-glance triage load

**Coming next:**
- PostgreSQL + Docker (Day 8)
- Real-time WebSocket dashboard (Day 9)
- Railway deployment (Day 10)

## Quick start

Requires Python 3.12+.

```bash
# Clone and enter the project
git clone https://github.com/RushilJain96/ai-siem-log-analyzer.git
cd ai-siem-log-analyzer

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
.venv\Scripts\Activate.ps1         # Windows PowerShell

# Install dependencies
pip install -r requirements-dev.txt

# Configure environment
cp .env.example .env

# Run the API
uvicorn api.main:app --reload

# Open the auto-generated docs
# http://localhost:8000/docs
```

## Running the tests

```bash
pytest tests/ -v
```

Tests use an in-memory SQLite database — no setup required, no real database touched.

## Loading sample data

The API is empty on a fresh clone. To seed it with real network flows from
CICIDS 2017:

```bash
# 1. Download MachineLearningCSV.zip from https://www.unb.ca/cic/datasets/ids-2017.html
#    and extract to ~/Downloads/MachineLearningCSV/MachineLearningCVE/ (or set CICIDS_DIR)

# 2. Produce a class-aware sample (~58K rows, ~18 MB)
python -m scripts.sample_cicids

# 3. Start the API in one terminal
uvicorn api.main:app

# 4. In another terminal, ingest N rows into the running API
python -m scripts.ingest_sample --count 5000

# 5. Verify
curl http://localhost:8000/stats
# {"total_logs": 5000, "total_alerts": <depends on the trained model>, "alert_rate": <depends>}
```

`total_alerts` reflects the trained detector's actual predictions (Day 5), not CICIDS's ground-truth labels — the count varies by how the model was trained and won't match any fixed number here. This requires a trained model (see "Fitting the feature pipeline" and "Training the detector" below) to be present *before* `scripts.ingest_sample` runs — the API only loads the model once, at startup.

### Fitting the feature pipeline

After loading sample data, fit the preprocessing pipeline used by the
anomaly detector:

```bash
python -m scripts.fit_pipeline
```

This produces `model/preprocessor.pkl`, a fitted StandardScaler plus
per-column medians for imputation at inference time. The script also
prints per-feature discrimination stats — attack rows should look
visibly shifted from the benign reference distribution on
discriminative features like `Packet Length Std` and `Flow IAT Max`.

The `.pkl` artifact is gitignored — each developer regenerates it
locally from their fitted pipeline.

The sample CSV and the SQLite database file are gitignored — each developer produces their own from their local CICIDS download.

### Training the detector

After fitting the feature pipeline, train the Isolation Forest anomaly detector:

```bash
python -m scripts.train_detector
```

This splits benign rows 80/20 (train/test) — **all attack rows are held
out for evaluation only**, never seen during training, per anomaly-detection
convention. It tunes the operational alert threshold (`decision_threshold`)
by maximizing recall subject to a 5% false-positive-rate budget, then
persists the fitted detector to `model/isolation_forest.pkl` (gitignored)
and the evaluation metrics to `model/metrics.json` (committed).

### Trying live detection

With both `.pkl` artifacts in place and the API running, POST a log with
`features` and the response comes back scored:

```bash
curl -X POST http://localhost:8000/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "event_time": "2026-07-11T12:00:00Z",
    "source_ip": "10.0.0.5",
    "features": {"Flow Duration": 40000000, "Flow Bytes/s": 2, "SYN Flag Count": 0}
  }'
# {"id": 1, ..., "anomaly_score": 0.87, "is_alert": true}   <- illustrative; your actual
#                                                              score depends on your locally
#                                                              trained model, not a fixed value
```

`features` accepts any subset of the 18 columns in
`model.features.FEATURE_COLUMNS` — omitted ones are imputed from the
fitted pipeline's medians, same as at training time. No `features` at
all (or no trained model loaded) leaves `is_alert: false` and
`anomaly_score: null`, same as every other field the client doesn't
control.

### Triaging alerts

Once logs are scored, query them by urgency:

```bash
# Alerts, most-anomalous first (critical at the top)
curl "http://localhost:8000/logs/alerts?limit=5"

# Just the critical tier
curl "http://localhost:8000/logs?severity=critical"

# Per-severity breakdown
curl http://localhost:8000/stats
# {"total_logs": 2000, "total_alerts": 235, "alert_rate": 0.1175,
#  "alerts_by_severity": {"low": 95, "medium": 48, "high": 83, "critical": 9}}
```

Severity is `low`/`medium`/`high`/`critical` for alerts, `null` for
non-alerts. An unknown `severity=` value is rejected with a 422.

## Model evaluation

- **Correction vs. the original project doc:** `contamination=0.01`, not `0.1` — it's sklearn's training-time noise allowance for the benign-only fit, not real-world attack prevalence (~19.6% in full CICIDS-2017). Its exact value turns out not to affect final tuned performance at all (see full writeup for why).
- **Current operating point** (5% FPR budget, tuned via ROC curve): recall 0.349, precision 0.908, FPR 0.050, adjusted precision 0.631. An F1-maximizing threshold was also tried and rejected — 95% recall at a 47% false-positive rate is unusable (alert fatigue).
- **Detection is uneven by attack type.** Strong on volumetric floods (DoS Hulk 67.6%, DDoS 41.5%) and Infiltration (80.6%). Near-zero on credential brute-forcing, port scanning, and web attacks (0–3%) — these need cross-flow or payload signals the current flow-shape-only features can't provide, not just a different threshold.
- **A sampler bug was found and fixed this day:** rows were sampled at a flat 2% regardless of attack type, despite being documented as "stratified." This silently reduced rare attack classes to statistical noise (or, for Infiltration, zero eval rows). Fixed with a class-aware floor; confirmed it changed measurement reliability, not the model itself.

**Per-attack-type recall** at the current operating point:

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

Full methodology, both operating-point tables, and the reasoning behind why each attack type lands where it does: **[docs/model-evaluation.md](docs/model-evaluation.md)**.

## Architecture

```
api/            FastAPI application
  main.py       App entry, lifespan, routes wired
  routes/       One file per resource (logs, stats)
core/           Cross-cutting concerns
  config.py     Env-var-driven settings (12-factor pattern)
  logging.py    Structured JSON logging
db/             Persistence layer
  database.py   Engine, session factory, init_db
  models.py     SQLAlchemy ORM tables
  crud.py       Read/write operations
model/          ML pipeline
  features.py   FeaturePipeline — fit/transform/save/load
  detector.py   Detector — Isolation Forest wrapper, scoring, evaluation
  inference.py  AnomalyScorer — composes FeaturePipeline+Detector for live /logs/ingest scoring
  severity.py   Maps anomaly_score → low/medium/high/critical tiers
scripts/        Operational scripts (not run in CI; touch real data)
  sample_cicids.py    Class-aware sampling from raw CICIDS CSVs
  fit_pipeline.py     Fits FeaturePipeline, saves model/preprocessor.pkl
  train_detector.py   Fits Detector, saves model/isolation_forest.pkl + metrics.json
tests/          pytest suite (synthetic data only — CI has no real CICIDS CSV)
docs/           Deeper writeups linked from this README (model evaluation, etc.)
.github/        GitHub Actions CI
```

Configuration is read exclusively through `core/config.py`. The rest of the codebase imports `settings` rather than touching `os.environ`. This means switching from local SQLite to production Postgres is a one-line change in `.env`.

## Tech stack

- **Backend:** FastAPI (ASGI), built on Starlette
- **ORM:** SQLAlchemy 2.0 with the typed `Mapped[T]` / `mapped_column()` syntax
- **Validation:** Pydantic v2
- **Database:** SQLite (dev), PostgreSQL planned for production
- **Testing:** pytest with FastAPI's TestClient (httpx-backed)
- **CI:** GitHub Actions running pytest on every push

## Known limitations

- Severity reflects **anomaly magnitude, not ground-truth maliciousness** — a limitation of unsupervised anomaly detection surfacing at the triage layer:
  - The detector learns "normal" from *typical* benign traffic, so an unusual-but-legitimate flow (e.g. a ~1.5 MB file transfer over ~100s) is genuinely far from that baseline.
  - Such a flow can therefore score `critical`, right next to real attacks — the model flags "statistically weird," not "malicious."
  - Observed directly in live testing: several top-scoring `critical` alerts were benign large transfers.
  - Mitigation (analyst feedback loop / mark-as-false-positive, or a supervised re-ranking layer) is a v2.0 item.
- SQLite strips timezone info on `DateTime(timezone=True)` columns — `event_time` round-trips as a naive datetime. Postgres (Day 8) will fix this.
- No authentication on any endpoint. Adding auth is a v2.0 item; the threat model for the portfolio scope is "trusted localhost client only."
- CICIDS 2017's MachineLearningCSV files have IP addresses stripped for privacy, so `source_ip` and `destination_ip` are always `null` in ingested rows. Would require `GeneratedLabelledFlows` or raw PCAPs to recover. This is also why per-source, cross-flow features (which would likely help detect PortScan and credential brute-forcing — see [Model evaluation](#model-evaluation)) aren't feasible with this dataset variant.
- Per-flow timestamps aren't available in the CICIDS ML CSVs. `event_time` is set to ingestion wall-clock.
- CICIDS Web Attack labels contain a Unicode replacement character (`�`) from a CP1252 → UTF-8 encoding mismatch in the original dataset. Doesn't affect binary classification.
- Feature selection is manual (18 columns hand-picked from CICIDS's 78). Automated selection via mutual information or variance thresholds is a v2.0 improvement.
- The feature pipeline drops rows with inf/NaN at fit time (~0.2% of benign rows lost). At transform time, imputation with learned medians is used instead so single-row inference doesn't fail.
- `Destination Port` is excluded from features to prevent trivial learning (attack ports map directly to attack types). Categorical port encoding is a v2.0 improvement.
- `Detector.save()` persists a plain dict payload (model, config, score_scale, decision_threshold, metadata), while `FeaturePipeline.save()` persists the whole fitted object via `joblib.dump(self)`. Two different persistence conventions for the two model classes — not yet reconciled, tracked as backlog.
- `RST Flag Count`'s attack-subset standard deviation is ≈0.000 (confirmed across two independently sampled datasets) — a near-constant column for attacks in this sample, not a strong standalone signal despite the nonzero mean shift. Low priority given it's one of 18 features, not worth dropping outright without checking its contribution to the trained forest.

## Roadmap

See the Day 1-of-10 status above for what's built and what's coming. v2.0 candidates (after the core 10-day build is shipped):

- Analyst feedback loop: mark alerts as false positives and feed that back into scoring/re-ranking, so benign outliers (large legitimate transfers) stop surfacing as critical — the mitigation for the severity limitation noted above
- Neural Network Autoencoder as an alternative detector to compare against Isolation Forest
- Cross-flow / per-source features (connection rate, distinct-port count in a time window) to address the PortScan and brute-force blind spot — blocked until a CICIDS variant with source IPs, or a different dataset, is used
- Ingesting real, self-captured system/network logs instead of CICIDS replay — would need a collector/agent that reshapes live traffic into the `/logs/ingest` schema (`event_time`, `source_ip`, `protocol`, `features`, etc.); the schema is designed to be general enough to support this later, but no capture pipeline exists yet
- Alembic migrations for production schema changes
- Alert correlation (group related alerts into incidents)
- MITRE ATT&CK mapping for detected anomalies
- RabbitMQ for async log ingestion at high throughput

## License

MIT.

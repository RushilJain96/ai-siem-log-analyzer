# AI-Driven SIEM Log Analyzer

> A cybersecurity tool that ingests network logs, detects anomalies via Isolation Forest, and surfaces high-risk alerts through a REST API. Built to understand how production SIEM tools (Splunk, Wazuh, Cortex XDR) work under the hood.

[![CI](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml)

## Status — Day 9 of 10

This project is being built incrementally. The current state covers the **foundation** (HTTP API, database, structured logging, CI), the **ML pipeline core** (feature engineering, anomaly detection, evaluation), **live detection wired into the API**, **alert triage** (severity tiers and filtering), a **containerized Postgres deployment** (Docker Compose), and a **real-time SOC dashboard** (WebSocket-driven). Cloud deployment is the last remaining piece.

**Working today:**
- FastAPI service with auto-generated OpenAPI docs at `/docs`
- SQLAlchemy 2.0 persistence — SQLite for local dev, **PostgreSQL via Docker Compose** (Day 8), swapped by a single `DATABASE_URL` change with zero DB-layer code changes
- Endpoints: `POST /logs/ingest`, `GET /logs` (with filters), `GET /logs/alerts`, `GET /stats`, `GET /model/info`, `GET /health`, `WS /ws`, and the live dashboard at `/dashboard`
- Structured JSON logging configured via environment variables
- pytest test suite covering ingest → list → stats, parser, feature pipeline, detector, live inference, end-to-end detection, severity, alert-filtering, WebSocket manager, and dashboard-endpoint tests (139 tests total)
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
- `anomaly_score` column indexed (Day 7) — it became a query+sort key on Day 6 (alerts ordering, severity range filters, the stats breakdown), so it's indexed by actual query pattern
- **Dockerized (Day 8):** a `Dockerfile` (non-root user, layer-cached deps, stdlib `/health` healthcheck) and `docker-compose.yml` bringing up the app + Postgres together — the app waits on a Postgres healthcheck before starting (`depends_on: service_healthy`). The trained model is provided via a read-only volume mount, so detection runs in-container if the `.pkl` exist locally and gracefully skips if not
- **Runs on PostgreSQL** with no code changes beyond `DATABASE_URL` — `db/database.py` needed only `pool_pre_ping` for networked-connection resilience. Verified live: data persists across a full `docker compose down`/`up` in a named Postgres volume, and timezone-aware timestamps round-trip correctly (the SQLite naive-datetime limitation is resolved on Postgres)
- **Real-time push (Day 9):** a `ConnectionManager` (`api/realtime.py`) fans every ingested log out to connected dashboards over a WebSocket (`WS /ws`). The interesting part: `POST /logs/ingest` is a *sync* route (Starlette runs it in a worker thread, correct for sync SQLAlchemy), while WebSockets live on the event loop — so the broadcast is bridged with `asyncio.run_coroutine_threadsafe` onto the loop captured at startup, fire-and-forget so ingest never blocks. No-ops cleanly when no dashboard is watching
- **Interpretable per-row signal (not model attribution):** `AnomalyScorer.score()` returns `top_features` — each feature's *standardized deviation from the benign baseline*. Because the pipeline scales to mean-0/std-1 on *benign* traffic, a feature's scaled value *is* its distance from normal in standard deviations, so "Bwd Packet Length Std is +4.1σ above baseline" tells an analyst **where** the row looks unusual. It is deliberately **not** the Isolation Forest's internal reason for isolating the row — the forest decides via path length across random splits, which has no per-feature contribution — and it isn't SHAP-style attribution. True model attribution would need a separate explainer (a v2.0 item); this is an honest proxy, labeled as such in the UI
- **Live SOC dashboard** at `/dashboard` — a dependency-free (no build step) dark-theme console: KPI cards (incl. *Detected Alerts* and *Avg Anomaly Score* — the raw mean IF score, not a calibrated probability), a live-computed AI Threat Index gauge, real-time log stream with quick severity filters, alerts feed, severity/category/timeline charts, a backend-backed **Log Explorer** (`GET /logs` with severity/IP/time/alert filters) reachable by clicking any severity to drill down, a real Model Status panel (`GET /model/info` reads live detector metadata), an **Observed Source Network Location** map, and a click-through AI Explanation drawer showing each row's largest baseline deviations. The map draws a *real* basemap — Natural Earth country boundaries projected to inline SVG at build time (`dashboard/worldmap.js`), so there's no map dependency or third-party tile call at runtime — and plots each source IP as a severity-coloured dot with a ring that pulses on new critical/high. Panels with no backing data (system health, MITRE ATT&CK, threat-intel feeds) are clearly badged **DEMO**; the map is badged **SIMULATED DATA** because an IP is a network endpoint, not a place, and we have no GeoIP/ASN enrichment yet (CICIDS also strips client IPs) — so a dot's *position* is a deterministic function of its source IP, not a real location. Real city/ASN/network-type enrichment plus a vector basemap (MapLibre) is a planned upgrade, deferred until the positions are real enough to justify it

**Coming next:**
- Cloud deployment (Day 10)

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

## Running with Docker (Postgres)

The API also runs containerized against PostgreSQL, via Docker Compose:

```bash
docker compose up --build -d      # builds the app image, starts app + Postgres
docker compose ps                 # wait until both show (healthy)
docker compose logs api           # startup: "Anomaly detector loaded" or graceful skip
curl http://localhost:8000/health # {"status":"ok"} — also proves the DB is reachable
```

Notes:
- The swap from SQLite is a single `DATABASE_URL` change (compose sets it to
  `postgresql+psycopg2://...@db:5432/...`) — no application code differs.
- The trained model is mounted read-only (`./model:/app/model:ro`). If you've
  run `fit_pipeline` + `train_detector` locally, the container picks up the
  `.pkl` and scores live; if not, it starts anyway and skips detection.
- Data persists in a named volume across `docker compose down`/`up`. Use
  `docker compose down -v` to wipe it.
- Credentials in `docker-compose.yml` are local-development defaults only —
  real secrets come from the deployment platform's environment.

## Live dashboard

With the API running (and a trained model loaded), open the real-time SOC
console:

```
http://localhost:8000/dashboard/
```

Open it **before** ingesting so you watch logs animate in live, then in
another terminal:

```bash
python -m scripts.ingest_sample --count 2000
```

Every ingested log is pushed over `WS /ws` as a `{"type": "log", ...}`
frame (all logs, not just alerts), and the dashboard updates the log
stream, KPIs, threat-index gauge, alerts, and charts in real time. Click
any log or alert to open the AI Explanation drawer — the "largest
deviations from benign baseline" there are each feature's real
standardized σ-distance from the learned baseline (an analyst signal for
*where* the row is unusual), not mock values and not the model's internal
attribution. Click any severity to open the Log Explorer, which queries
`GET /logs` with real filters. The Model Status panel reads live detector
metadata from `GET /model/info`. Without a trained model the dashboard
still loads and honestly shows Model Status as "unavailable."

Panels backed by real data: KPIs, threat index, live stream, alerts,
severity/category/timeline charts, AI explanation, model status. Panels
badged **DEMO** (mock data, designed for future integration): system
health, MITRE ATT&CK coverage, threat-intel feed.

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
  main.py       App entry, lifespan, routes wired, dashboard mount
  realtime.py   WebSocket ConnectionManager + sync→async broadcast bridge
  routes/       One file per resource (logs, stats, dashboard/WS)
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
  inference.py  AnomalyScorer — scoring + top baseline-deviation signal
  severity.py   Maps anomaly_score → low/medium/high/critical tiers
dashboard/      Live SOC dashboard (static, dependency-free HTML/CSS/JS)
scripts/        Operational scripts (not run in CI; touch real data)
  sample_cicids.py    Class-aware sampling from raw CICIDS CSVs
  fit_pipeline.py     Fits FeaturePipeline, saves model/preprocessor.pkl
  train_detector.py   Fits Detector, saves model/isolation_forest.pkl + metrics.json
tests/          pytest suite (synthetic data only — CI has no real CICIDS CSV)
docs/           Deeper writeups linked from this README (model evaluation, etc.)
.github/        GitHub Actions CI
Dockerfile          App image (non-root, healthcheck)
docker-compose.yml  App + Postgres stack for local containerized runs
.dockerignore       Keeps secrets/data/models out of the build context
```

Configuration is read exclusively through `core/config.py`. The rest of the codebase imports `settings` rather than touching `os.environ`. This is what made the Day 8 SQLite→Postgres swap a one-line `DATABASE_URL` change with no application code touched.

## Tech stack

- **Backend:** FastAPI (ASGI), built on Starlette
- **Real-time:** WebSockets (FastAPI/Starlette native), sync→async broadcast bridge
- **Frontend:** dependency-free HTML/CSS/JS (no build step, no framework), dark SOC theme
- **ORM:** SQLAlchemy 2.0 with the typed `Mapped[T]` / `mapped_column()` syntax
- **Validation:** Pydantic v2
- **Database:** SQLite (local dev), PostgreSQL (via Docker Compose)
- **Containers:** Docker + Docker Compose (app + Postgres)
- **Testing:** pytest with FastAPI's TestClient (httpx-backed)
- **CI:** GitHub Actions running pytest on every push

## Known limitations

- Severity reflects **anomaly magnitude, not ground-truth maliciousness** — a limitation of unsupervised anomaly detection surfacing at the triage layer:
  - The detector learns "normal" from *typical* benign traffic, so an unusual-but-legitimate flow (e.g. a ~1.5 MB file transfer over ~100s) is genuinely far from that baseline.
  - Such a flow can therefore score `critical`, right next to real attacks — the model flags "statistically weird," not "malicious."
  - Observed directly in live testing: several top-scoring `critical` alerts were benign large transfers.
  - Mitigation (analyst feedback loop / mark-as-false-positive, or a supervised re-ranking layer) is a v2.0 item.
- SQLite (the local-dev default) strips timezone info on `DateTime(timezone=True)` columns — `event_time` round-trips as a *naive* datetime. **Resolved on Postgres** (Day 8): running via Docker Compose, timestamps round-trip timezone-aware (verified — `event_time` comes back with a UTC offset). This is a SQLite limitation, not an application one.
- No authentication on any endpoint. Adding auth is a v2.0 item; the threat model for the portfolio scope is "trusted localhost client only."
- CICIDS 2017's MachineLearningCSV files have IP addresses stripped for privacy, so `source_ip` and `destination_ip` are always `null` in ingested rows. Would require `GeneratedLabelledFlows` or raw PCAPs to recover. This is also why per-source, cross-flow features (which would likely help detect PortScan and credential brute-forcing — see [Model evaluation](#model-evaluation)) aren't feasible with this dataset variant.
- Per-flow timestamps aren't available in the CICIDS ML CSVs. `event_time` is set to ingestion wall-clock.
- CICIDS Web Attack labels contain a Unicode replacement character (`�`) from a CP1252 → UTF-8 encoding mismatch in the original dataset. Doesn't affect binary classification.
- Feature selection is manual (18 columns hand-picked from CICIDS's 78). Automated selection via mutual information or variance thresholds is a v2.0 improvement.
- The feature pipeline drops rows with inf/NaN at fit time (~0.2% of benign rows lost). At transform time, imputation with learned medians is used instead so single-row inference doesn't fail.
- `Destination Port` is excluded from features to prevent trivial learning (attack ports map directly to attack types). Categorical port encoding is a v2.0 improvement.
- `Detector.save()` persists a plain dict payload (model, config, score_scale, decision_threshold, metadata), while `FeaturePipeline.save()` persists the whole fitted object via `joblib.dump(self)`. Two different persistence conventions for the two model classes — not yet reconciled, tracked as backlog.
- `RST Flag Count`'s attack-subset standard deviation is ≈0.000 (confirmed across two independently sampled datasets) — a near-constant column for attacks in this sample, not a strong standalone signal despite the nonzero mean shift. Low priority given it's one of 18 features, not worth dropping outright without checking its contribution to the trained forest.
- The dashboard broadcasts **every** ingested log to all connected clients (so the live stream shows benign traffic too), and every client receives every log (no per-client filtering or auth on `WS /ws`). Fine at demo ingest rates on trusted localhost; at production throughput you'd throttle, sample, or split alert/log channels, and gate the socket behind the same auth the API lacks (a v2.0 item).
- Several dashboard panels are **DEMO / mock data**, clearly badged as such: system health (CPU/RAM/disk — not measured), MITRE ATT&CK coverage (no real ATT&CK mapping engine — a hand-coded event→technique lookup), and the threat-intel feed (no live IOC integration). They're built to show the intended layout for future integration, not to imply the data is real. Everything else on the dashboard is real backend data.

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

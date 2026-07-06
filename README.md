# AI-Driven SIEM Log Analyzer

> A cybersecurity tool that ingests network logs, detects anomalies via Isolation Forest, and surfaces high-risk alerts through a REST API. Built to understand how production SIEM tools (Splunk, Wazuh, Cortex XDR) work under the hood.

[![CI](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml)

## Status — Day 3 of 10

This project is being built incrementally. The current state is the **foundation**: HTTP API, database, structured logging, CI. The ML detection pipeline and dashboard are upcoming.

**Working today:**
- FastAPI service with auto-generated OpenAPI docs at `/docs`
- SQLite persistence layer using SQLAlchemy 2.0
- Endpoints: `POST /logs/ingest`, `GET /logs`, `GET /stats`, `GET /health`
- Structured JSON logging configured via environment variables
- pytest test suite covering the full ingest → list → stats flow, plus parser unit tests (20 tests total)
- GitHub Actions CI running tests on every push
- Chunked sampler producing a 2% stratified sample from the eight CICIDS 2017 CSVs
- CICIDS row parser handling the dataset's known quirks (leading whitespace in column names, `inf`/`NaN` in flow-rate columns, missing IPs)
- HTTP-driven ingestion pipeline that seeds the database from parsed CICIDS rows
- Feature engineering pipeline: 15 hand-selected flow-shape features (volume, rate, packet size, timing)
- StandardScaler-based normalization fitted on benign rows only to prevent training-time data leakage
- Fitted preprocessing pipeline persisted to disk via `joblib` for reuse at inference time
- Per-feature discrimination analysis run at fit time — confirms attack rows shift up to +2.4 std devs on packet-length features

**Coming next:**
- Isolation Forest training and evaluation (Day 4)
- End-to-end detection wired into `POST /logs/ingest` (Day 5)
- Alert filtering and severity (Day 6)
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

# 2. Produce a 2% stratified sample (~56K rows, ~18 MB)
python -m scripts.sample_cicids

# 3. Start the API in one terminal
uvicorn api.main:app

# 4. In another terminal, ingest N rows into the running API
python -m scripts.ingest_sample --count 5000

# 5. Verify
curl http://localhost:8000/stats
# {"total_logs":5000,"total_alerts":992,"alert_rate":0.1984}
```

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
tests/          pytest suite
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

- SQLite strips timezone info on `DateTime(timezone=True)` columns — `event_time` round-trips as a naive datetime. Postgres (Day 8) will fix this.
- No authentication on any endpoint. Adding auth is a v2.0 item; the threat model for the portfolio scope is "trusted localhost client only."
- The `/logs/ingest` endpoint does not yet run anomaly detection — it persists the structured fields and returns. The detection wiring lands on Day 5.
- CICIDS 2017's MachineLearningCSV files have IP addresses stripped for privacy, so `source_ip` and `destination_ip` are always `null` in ingested rows. Would require `GeneratedLabelledFlows` or raw PCAPs to recover.
- Per-flow timestamps aren't available in the CICIDS ML CSVs. `event_time` is set to ingestion wall-clock.
- `LogIngest` accepts `is_alert` and `anomaly_score` from clients as a Day-2 seed-data shortcut using CICIDS ground-truth labels. Day 5 removes these fields once the server-side detector produces them.
- CICIDS Web Attack labels contain a Unicode replacement character (`�`) from a CP1252 → UTF-8 encoding mismatch in the original dataset. Doesn't affect binary classification.
- Feature selection is manual (15 columns hand-picked from CICIDS's 78). Automated selection via mutual information or variance thresholds is a v2.0 improvement.
- The feature pipeline drops rows with inf/NaN at fit time (~0.2% of benign rows lost). At transform time, imputation with learned medians is used instead so single-row inference doesn't fail.
- `Destination Port` is excluded from features to prevent trivial learning (attack ports map directly to attack types). Categorical port encoding is a v2.0 improvement.

## Roadmap

See the Day 1-of-10 status above for what's built and what's coming. v2.0 candidates (after the core 10-day build is shipped):

- Neural Network Autoencoder as an alternative detector to compare against Isolation Forest
- Alembic migrations for production schema changes
- Alert correlation (group related alerts into incidents)
- MITRE ATT&CK mapping for detected anomalies
- RabbitMQ for async log ingestion at high throughput

## License

MIT.
# AI-Driven SIEM Log Analyzer

> A cybersecurity tool that ingests network logs, detects anomalies via Isolation Forest, and surfaces high-risk alerts through a REST API. Built to understand how production SIEM tools (Splunk, Wazuh, Cortex XDR) work under the hood.

[![CI](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/RushilJain96/ai-siem-log-analyzer/actions/workflows/ci.yml)

## Status — Day 1 of 10

This project is being built incrementally. The current state is the **foundation**: HTTP API, database, structured logging, CI. The ML detection pipeline and dashboard are upcoming.

**Working today:**
- FastAPI service with auto-generated OpenAPI docs at `/docs`
- SQLite persistence layer using SQLAlchemy 2.0
- Endpoints: `POST /logs/ingest`, `GET /logs`, `GET /stats`, `GET /health`
- Structured JSON logging configured via environment variables
- pytest test suite covering the full ingest → list → stats flow
- GitHub Actions CI running tests on every push

**Coming next:**
- CICIDS 2017 dataset ingestion and parsing (Day 2)
- Feature engineering pipeline (Day 3)
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

## Roadmap

See the Day 1-of-10 status above for what's built and what's coming. v2.0 candidates (after the core 10-day build is shipped):

- Neural Network Autoencoder as an alternative detector to compare against Isolation Forest
- Alembic migrations for production schema changes
- Alert correlation (group related alerts into incidents)
- MITRE ATT&CK mapping for detected anomalies
- RabbitMQ for async log ingestion at high throughput

## License

MIT.
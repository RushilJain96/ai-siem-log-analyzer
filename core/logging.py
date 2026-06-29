"""
Structured JSON logging for the SIEM service.

This module configures Python's root logger to emit single-line JSON
to stdout. Container platforms (Docker, Railway) collect stdout and
forward it to whatever aggregator is configured downstream — locally
we read it ourselves, in production it goes to the platform's log
stream.

Design notes:
- JSON output, never plain text. This is a SIEM; structured logs are
  the product.
- stdout only, no file handlers. Containers capture stdout natively.
  Writing to files inside a container is an anti-pattern (logs vanish
  when the container restarts).
- The log level is read from settings, which means LOG_LEVEL in .env
  (or in Railway's env vars) controls verbosity without code changes.
"""
import json
import logging
import sys
from datetime import datetime, timezone

from core.config import settings


# Standard LogRecord attributes that we don't want duplicated into our
# JSON output. When a user passes extra={...} to a log call, those
# extras land on the LogRecord as instance attributes alongside Python's
# own internal fields. We need to skip the internal ones.
_RESERVED_LOG_ATTRS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
})


class JsonFormatter(logging.Formatter):
    """Format each log record as a single line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include exception traceback if the log call was logger.exception()
        # or logger.error("...", exc_info=True). Without this, exceptions
        # would silently lose their tracebacks in the JSON output.
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Include any extra fields the caller attached via extra={...}.
        # E.g., logger.info("ingested", extra={"source_ip": "10.0.0.1"})
        # results in {"source_ip": "10.0.0.1"} merged into the JSON output.
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_ATTRS and not key.startswith("_"):
                payload[key] = value

        # default=str makes datetimes, UUIDs, and other non-JSON-native
        # types serialize via their __str__ rather than raising TypeError.
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """
    Configure the root logger to emit JSON to stdout.

    Idempotent: safe to call multiple times. We strip any pre-existing
    handlers before adding ours, so calling configure_logging() twice
    doesn't produce duplicated log lines.

    Should be called once at application startup, before any other
    logging calls. We invoke it from api/main.py before creating the
    FastAPI app.
    """
    root = logging.getLogger()
    root.setLevel(settings.log_level)

    # Remove any handlers libraries may have installed before us.
    # Without this, third-party libraries that called logging.basicConfig()
    # at import time leave a default StreamHandler attached, and our
    # JSON output gets interleaved with plain-text output from that handler.
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)

    # Uvicorn installs its own access-log handler with a custom formatter.
    # Override it so HTTP request logs also come out as JSON. Otherwise
    # half our logs are JSON and half are uvicorn's plain text — the worst
    # of both worlds for any log aggregator.
    uvicorn_access = logging.getLogger("uvicorn.access")
    uvicorn_access.handlers = [handler]
    uvicorn_access.propagate = False
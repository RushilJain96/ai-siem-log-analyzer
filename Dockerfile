# syntax=docker/dockerfile:1
#
# Container image for the SIEM API (Day 8).
#
# Design notes:
# - python:3.12-slim: matches the project's Python version, far smaller
#   than the full python image. sklearn/pandas/numpy still make this a
#   few hundred MB — inherent to an ML service, not fixable by a lighter
#   base.
# - Requirements are copied and installed BEFORE the app code, so the
#   (slow) pip-install layer is cached and only re-runs when
#   requirements change — not on every code edit.
# - Runs as a non-root user: if the app is ever compromised, the
#   attacker lands as an unprivileged user, not root inside the
#   container. Cheap, standard hardening.
# - CMD binds 0.0.0.0 (not 127.0.0.1) so the port is reachable from
#   outside the container, and honors $PORT: managed platforms (Render,
#   etc.) inject the port they route to via $PORT and expect the app to
#   listen on it. We default to 8000 for local/compose use.

FROM python:3.12-slim

# Don't buffer stdout/stderr — logs appear immediately in `docker logs`
# instead of being held in a buffer until the process exits. And don't
# write .pyc files; they're pointless in an ephemeral container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first (cached layer). requirements.txt holds the
# runtime deps; dev-only tooling (pytest) isn't needed to run the app.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Now the application code. Changing code invalidates only this layer,
# not the dependency install above.
COPY . .

# Create and switch to an unprivileged user, owning /app so the app can
# read its code and the mounted model directory.
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Liveness/readiness probe. /health does a real SELECT 1, so a passing
# healthcheck also confirms the database is reachable. Uses stdlib
# urllib so we don't have to add curl to the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request, sys; \
port = os.getenv('PORT', '8000'); \
sys.exit(0 if urllib.request.urlopen(f'http://localhost:{port}/health').status == 200 else 1)"

# `sh -c` so ${PORT} is expanded at runtime (JSON/exec form does no env
# substitution); `exec` so uvicorn REPLACES the shell as PID 1 and receives
# SIGTERM directly — otherwise the shell swallows it and shutdown isn't
# graceful (matters for zero-downtime redeploys/restarts). Falls back to
# 8000 when PORT isn't set (local/compose).
CMD ["sh", "-c", "exec uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
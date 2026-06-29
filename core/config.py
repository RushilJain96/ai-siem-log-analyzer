"""
Centralized configuration loaded from environment variables.

This module is the ONLY place in the codebase that reads from os.environ.
Every other module imports `settings` from here. This means changing how
config is loaded (e.g., switching from .env to AWS Parameter Store)
requires touching only this file.

Pattern: 12-factor config — https://12factor.net/config
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

# load_dotenv() reads .env into os.environ.
#
# - Called once, at module import time.
# - If .env doesn't exist (e.g., in production where env vars are set
#   by the platform), this silently does nothing. Correct behavior.
# - Does NOT override variables that are already set in the environment.
#   Production env vars always win over .env file. This is intentional —
#   it's how you override .env locally for one-off testing.
load_dotenv()


@dataclass(frozen=True)
class Settings:
    """
    Typed, immutable configuration object.

    `frozen=True` prevents accidental mutation. If some code somewhere
    tries `settings.database_url = "..."`, it raises FrozenInstanceError
    instead of silently corrupting config mid-request.
    """
    database_url: str
    log_level: str
    app_name: str
    app_env: str


def _load_settings() -> Settings:
    """
    Read environment variables and construct the Settings object.

    Leading underscore = "private to this module" (Python convention,
    not enforced). External code should import `settings`, not call
    this function directly.

    Every getenv() call provides a default. The app must boot even
    with zero environment variables set, so someone cloning the repo
    can run it immediately without configuring anything.
    """
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./siem.db"),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        app_name=os.getenv("APP_NAME", "siem-log-analyzer"),
        app_env=os.getenv("APP_ENV", "development"),
    )


# Module-level singleton. Created once at first import.
# Import this anywhere: `from core.config import settings`
settings = _load_settings()
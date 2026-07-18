"""Model-artifact integrity: the model card + hash verification (Day 10).

Binds the exact (preprocessor, detector) pair the app loads to a single
machine-readable release record — model/model_card.json — and verifies
each artifact's SHA-256 against that card BEFORE anything deserializes
them.

Why verify before load: joblib.load() ultimately unpickles, and
unpickling untrusted or modified bytes can execute arbitrary code. Hashing
the raw bytes first (no deserialization) lets us refuse a tampered or
corrupted artifact before it can do harm. So the order is always:

    read bytes -> sha256 -> compare to card -> only then joblib.load

One shared implementation used by BOTH sides:
  - scripts/train_detector.py calls write_model_card() right after it saves
    the artifacts, so the card is produced by the same run (no drift).
  - model/inference.py calls verify_model_artifacts() before loading.

What this protects against: accidental corruption, a model/card mismatch,
an old preprocessor paired with a new detector, a Docker build that
dropped or altered an artifact, or someone swapping a .pkl without updating
the record. What it does NOT protect against: an attacker who can edit BOTH
the artifacts and the card in the repo/image — that needs signed
releases/manifests, a deliberate later tier.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import platform
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

# Bump when the card's structure changes incompatibly. verify refuses a
# card whose schema_version it doesn't recognise.
CARD_SCHEMA_VERSION = 1

_CHUNK = 1 << 20  # 1 MiB — hash in chunks so this stays correct as models grow


class ModelArtifactIntegrityError(RuntimeError):
    """Model artifacts are present but do not match their approved card.

    Raised for a missing-but-expected file, a malformed/unsupported card,
    or a SHA-256 mismatch. This is a FAIL-CLOSED signal: the application
    must refuse to load the model rather than run without the approved one.
    Deliberately NOT a subclass of FileNotFoundError, so the 'no model at
    all' graceful path and the 'something is wrong' fatal path can be
    caught separately.
    """


def sha256_file(path: Path | str, chunk_size: int = _CHUNK) -> str:
    """SHA-256 of a file's raw bytes, read in chunks (memory-bounded)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version(distribution: str) -> str:
    try:
        return version(distribution)
    except PackageNotFoundError:
        return "unknown"


def _runtime_versions() -> dict[str, str]:
    """The interpreter + library versions the artifacts were produced with.

    Pickled sklearn objects are only reliably loadable under matching
    library versions, so recording these makes a load failure diagnosable
    ('trained on sklearn 1.4.2, running 1.6') instead of mysterious."""
    return {
        "python": platform.python_version(),
        "scikit_learn": _package_version("scikit-learn"),
        "joblib": _package_version("joblib"),
    }


def _write_json_atomically(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON via a temp file + atomic replace, so an interrupted run
    never leaves a half-written (and thus unverifiable) card. allow_nan is
    off: a NaN/inf metric would otherwise emit invalid JSON that fails to
    parse later — better to fail loudly here."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def write_model_card(
    card_path: Path | str,
    *,
    artifacts: dict[str, Path],
    artifact_version: str,
    training: dict,
    evaluation: dict,
    training_data: dict | None = None,
    limitations: list[str] | None = None,
) -> dict:
    """Write the release record binding these exact artifacts (by hash).

    `artifacts` maps a logical name (e.g. "preprocessor.pkl") to the file
    on disk. Called at training time, so the recorded hashes describe the
    files that run produced. The runtime versions are captured
    automatically. Returns the written card dict.
    """
    card = {
        "schema_version": CARD_SCHEMA_VERSION,
        "artifact_version": artifact_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": {
            name: {"sha256": sha256_file(path), "bytes": Path(path).stat().st_size}
            for name, path in artifacts.items()
        },
        "training": training,
        "evaluation": evaluation,
        "runtime": _runtime_versions(),
        "limitations": limitations or [],
    }
    if training_data is not None:
        card["training_data"] = training_data
    _write_json_atomically(Path(card_path), card)
    return card


def load_card(card_path: Path | str) -> dict:
    """Parse and structurally validate the card. Raises
    ModelArtifactIntegrityError on unreadable/malformed JSON or an
    unsupported schema_version — never returns a card we can't trust."""
    try:
        card = json.loads(Path(card_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelArtifactIntegrityError(
            f"Model card {card_path} is unreadable or malformed: {exc}"
        ) from exc
    if card.get("schema_version") != CARD_SCHEMA_VERSION:
        raise ModelArtifactIntegrityError(
            f"Unsupported model card schema_version "
            f"{card.get('schema_version')!r} (expected {CARD_SCHEMA_VERSION})."
        )
    if not isinstance(card.get("artifacts"), dict):
        raise ModelArtifactIntegrityError("Model card is missing its 'artifacts' block.")
    return card


def verify_model_artifacts(card_path: Path | str, artifacts: dict[str, Path]) -> dict:
    """Verify each artifact's SHA-256 against the card BEFORE any load.

    Returns the parsed card on success. Raises ModelArtifactIntegrityError
    on a malformed/unsupported card or any hash mismatch. Deserializes
    nothing — it only reads bytes and hashes them. The comparison uses
    hmac.compare_digest as a good habit; there's no timing oracle to exploit
    here (whoever can change a file already knows its hash), so it's
    belt-and-suspenders, not load-bearing.
    """
    card = load_card(card_path)
    recorded = card["artifacts"]
    for name, path in artifacts.items():
        entry = recorded.get(name)
        if not entry or "sha256" not in entry:
            raise ModelArtifactIntegrityError(
                f"Model card has no recorded hash for artifact {name!r}."
            )
        actual = sha256_file(path)
        expected = entry["sha256"]
        if not hmac.compare_digest(expected, actual):
            raise ModelArtifactIntegrityError(
                f"SHA-256 mismatch for {name}: card expects {expected[:12]}…, "
                f"file is {actual[:12]}…. Refusing to load a modified artifact."
            )
    return card

"""Read-only N3 baseline management API.

Registers GET /api/baselines on the existing Flask application.
Uses the current N3 baseline modules instead of bypassing verification.
Never returns raw card memory, stored HMAC values, or secret material.
"""

from pathlib import Path
import json
import sys

from flask import jsonify

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from baseline_version_manager import (  # noqa: E402
    BASELINES_DIR,
    get_existing_baseline_versions,
    get_latest_baseline_version,
    get_active_baseline_version,
    normalize_card_type,
    normalize_uid,
)
from baseline_manager import load_baseline  # noqa: E402
from crypto_engine import HMAC_KEY_FILE  # noqa: E402


def _safe_text(value):
    return value.strip() if isinstance(value, str) else ""


def _baseline_identity_from_file(path):
    """Read *only* identity for discovery; verify before trusting metadata."""
    with path.open("r", encoding="utf-8") as stream:
        baseline = json.load(stream)
    if not isinstance(baseline, dict):
        raise ValueError("Invalid baseline structure")

    card = baseline.get("card_info")
    if not isinstance(card, dict):
        raise ValueError("Missing card_info")

    card_family = _safe_text(card.get("card_family")) or _safe_text(
        card.get("card_type")
    )
    uid = _safe_text(card.get("uid"))
    if not card_family or not uid:
        raise ValueError("Missing card identity")
    return card_family, uid


def _build_card_summary(card_type, uid):
    """Verify versions using existing N3 loader; no writes to baselines."""
    versions = get_existing_baseline_versions(card_type, uid)
    if not versions:
        return None

    latest_version = get_latest_baseline_version(card_type, uid)
    pointer_error = None
    try:
        active_version = get_active_baseline_version(card_type, uid)
    except (OSError, ValueError, TypeError) as error:
        active_version = None
        pointer_error = str(error)

    entries = []
    for version in versions:
        entry = {
            "version": version,
            "is_active": (active_version is not None and version == active_version),
            "integrity": "NOT_VERIFIED",
            "enrollment_time_utc": None,
            "source_file": None,
        }

        # Very important: load_baseline() generates a new key if missing.
        # Do not create/recreate the trusted key simply by viewing this page.
        if not HMAC_KEY_FILE.is_file():
            entry["integrity"] = "KEY_MISSING"
        else:
            try:
                trusted_baseline, _path = load_baseline(
                    card_type, uid, version=version
                )
                entry["integrity"] = "VERIFIED"
                entry["enrollment_time_utc"] = trusted_baseline.get(
                    "enrollment_time_utc"
                )
                entry["source_file"] = trusted_baseline.get("source_file")
            except FileNotFoundError:
                entry["integrity"] = "MISSING"
            except (OSError, ValueError, TypeError, KeyError):
                entry["integrity"] = "FAILED"

        entries.append(entry)

    return {
        "card_family": card_type,
        "uid": uid,
        "active_version": active_version,
        "latest_version": latest_version,
        "active_pointer_error": pointer_error,
        "versions": entries,
    }


def load_baseline_summaries():
    """List enrolled cards using the existing baseline repository."""
    if not BASELINES_DIR.is_dir():
        return {"cards": [], "skipped_files": 0}

    identity_map = {}
    skipped_files = 0

    for path in BASELINES_DIR.glob("*_V*.json"):
        if not path.is_file():
            continue
        try:
            card_type, uid = _baseline_identity_from_file(path)
            key = (normalize_card_type(card_type), normalize_uid(uid))
            if not key[0] or not key[1]:
                raise ValueError("Invalid normalized identity")
            identity_map.setdefault(key, (card_type, uid))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            skipped_files += 1

    cards = []
    for (normalized_type, normalized_uid), (card_type, uid) in sorted(
        identity_map.items()
    ):
        try:
            result = _build_card_summary(card_type, uid)
        except (OSError, ValueError, TypeError):
            skipped_files += 1
            continue
        if result is not None:
            cards.append(result)

    return {"cards": cards, "skipped_files": skipped_files}


def register_baseline_routes(app):
    """Add a single safe GET endpoint to the existing N3 dashboard."""

    @app.get("/api/baselines")
    def api_baselines():
        try:
            result = load_baseline_summaries()
        except (OSError, ValueError, TypeError) as exc:
            return jsonify({
                "status": "ERROR",
                "message": "Baseline metadata could not be loaded.",
                "error": str(exc),
            }), 500

        cards = result["cards"]
        return jsonify({
            "status": "OK",
            "read_only": True,
            "total_cards": len(cards),
            "total_versions": sum(len(card["versions"]) for card in cards),
            "skipped_files": result["skipped_files"],
            "cards": cards,
        })

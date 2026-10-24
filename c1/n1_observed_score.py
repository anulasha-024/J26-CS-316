"""N1 Viva-1 observed-factor prototype score.

Implements the user's current rules exactly:
- factor values -> 0 / 0.5 / 1
- UNKNOWN excluded from score but reduces evidence coverage
- Not Applicable excluded from score and coverage denominator
- score = average(known applicable factor risk values) * 100
- evidence coverage = known applicable / applicable * 100

This is NOT a Cox-calibrated score and NOT attack probability.
"""
from __future__ import annotations
import csv
import re
from pathlib import Path

FACTORS = [
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
]

# Confirmed mappings already established in the user's N1 lab notes.
KNOWN_UID_TO_CARD = {
    "040372A0310289": "NTAG215_01",
    "04A3C090310289": "NTAG215_02",
}


def _norm(v):
    return re.sub(r"[\s_\-/]+", " ", str(v or "").strip().lower())


def _is_unknown(v):
    n = _norm(v)
    return n in {"", "unknown", "unverified", "not verified", "pending", "n k", "na unknown"}


def _is_na(v):
    n = _norm(v)
    return n in {"n a", "na", "not applicable", "notapplicable", "not applicable to card"}


def _map_factor(name, value):
    """Return (risk_value, state) where state is KNOWN / UNKNOWN / NOT_APPLICABLE."""
    if _is_na(value):
        return None, "NOT_APPLICABLE"
    if _is_unknown(value):
        return None, "UNKNOWN"
    n = _norm(value)

    if name == "uid_writable":
        if n in {"not writable", "fixed", "read only", "readonly"}: return 0.0, "KNOWN"
        if "partial" in n: return 0.5, "KNOWN"
        if n in {"writable", "writeable"}: return 1.0, "KNOWN"

    elif name == "auth_type":
        if "no authentication" in n or n in {"none", "no auth"}: return 1.0, "KNOWN"
        if "crypto1" in n or "weak" in n or "mifare classic" in n: return 0.5, "KNOWN"
        if "aes" in n or "strong" in n: return 0.0, "KNOWN"

    elif name == "default_key_present":
        if n in {"yes", "true", "1", "present", "default key present"}: return 1.0, "KNOWN"
        if n in {"no", "false", "0", "not present", "default key not present", "absent"}: return 0.0, "KNOWN"

    elif name == "lock_state":
        if n == "unlocked": return 1.0, "KNOWN"
        if "partial" in n: return 0.5, "KNOWN"
        if n == "locked": return 0.0, "KNOWN"

    elif name == "ndef_protection":
        if n == "unprotected": return 1.0, "KNOWN"
        if "partial" in n or "password" in n: return 0.5, "KNOWN"
        if n == "protected": return 0.0, "KNOWN"

    elif name == "cve_flag":
        if n in {"yes", "true", "1", "known cve", "cve present", "known"}: return 1.0, "KNOWN"
        if n in {"no", "false", "0", "no known cve", "none", "not found"}: return 0.0, "KNOWN"

    # Unrecognized text is evidence-unknown; never silently score as safe.
    return None, "UNKNOWN"


def _compact_uid(v):
    return re.sub(r"[^0-9A-Fa-f]", "", str(v or "")).upper()


def _row_card_id(row):
    for key in ("card_instance", "card_id", "config_id", "id", "name"):
        if row.get(key):
            return str(row[key]).strip()
    return ""


def _row_uid(row):
    for key in ("uid", "card_uid", "UID", "Card UID", "card uid"):
        if row.get(key):
            return _compact_uid(row[key])
    return ""


def _load_configs(project_root):
    path = Path(project_root) / "Datasets" / "configs.csv"
    if not path.is_file():
        return path, []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return path, list(csv.DictReader(f))


def _match_row(card, rows):
    uid = _compact_uid(card.get("uid"))
    # Preferred: exact UID stored in configs.csv.
    uid_matches = [r for r in rows if _row_uid(r) and _row_uid(r) == uid]
    if len(uid_matches) == 1:
        return uid_matches[0], _row_card_id(uid_matches[0]) or uid
    if len(uid_matches) > 1:
        return None, None

    # Next: confirmed UID-to-card mapping for the two NTAG215 lab tags.
    card_id = KNOWN_UID_TO_CARD.get(uid)
    if card_id:
        id_matches = [r for r in rows if _row_card_id(r).upper() == card_id.upper()]
        if len(id_matches) == 1:
            return id_matches[0], card_id

    return None, None


def score_known_card(card, project_root):
    path, rows = _load_configs(project_root)
    if not rows:
        return {
            "status": "UNAVAILABLE", "reason": "configs.csv not found or empty",
            "score": None, "coverage": None, "preliminary_score": None,
            "final_cox_score": None, "card_id": None, "factors": [],
            "method": "OBSERVED_FACTOR_AVERAGE_V1",
        }

    row, card_id = _match_row(card, rows)
    if row is None:
        return {
            "status": "UNMAPPED_CARD",
            "reason": "UID is not uniquely mapped to a configs.csv card profile",
            "score": None, "coverage": None, "preliminary_score": None,
            "final_cox_score": None, "card_id": None, "factors": [],
            "method": "OBSERVED_FACTOR_AVERAGE_V1",
        }

    items = []
    applicable = 0
    known = 0
    risk_sum = 0.0
    for factor in FACTORS:
        raw = row.get(factor, "UNKNOWN")
        risk, state = _map_factor(factor, raw)
        if state != "NOT_APPLICABLE":
            applicable += 1
        if state == "KNOWN":
            known += 1
            risk_sum += risk
        items.append({
            "factor": factor,
            "observed": raw if str(raw).strip() else "UNKNOWN",
            "state": state,
            "risk_value": risk,
        })

    score = round((risk_sum / known) * 100, 1) if known else None
    coverage = round((known / applicable) * 100, 1) if applicable else None
    return {
        "status": "READY" if score is not None else "INSUFFICIENT_EVIDENCE",
        "reason": "Known applicable factors averaged; UNKNOWN excluded; Not Applicable excluded",
        "card_id": card_id,
        "uid": _compact_uid(card.get("uid")),
        "score": score,
        "coverage": coverage,
        "preliminary_score": score,
        "final_cox_score": None,
        "known_applicable": known,
        "applicable_total": applicable,
        "factors": items,
        "method": "OBSERVED_FACTOR_AVERAGE_V1",
        "source": str(path),
    }

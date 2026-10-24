import csv
from pathlib import Path

file = Path("Datasets/exp02_trials.csv")

required = {
    "trial_id",
    "card_id",
    "planned_auth0",
    "scenario",
    "attacker_tier",
    "outcome",
    "event_observed",
    "right_censored",
    "ttc_seconds",
    "evidence_path",
    "status"
}

if not file.exists():
    raise RuntimeError("DATASET NOT FOUND")

with file.open("r", encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    columns = set(reader.fieldnames or [])
    rows = list(reader)

missing = required - columns

if missing:
    raise RuntimeError(
        f"MISSING COLUMNS: {sorted(missing)}"
    )

expected_ids = {
    "EXP02-T01",
    "EXP02-T02",
    "EXP02-T03"
}

ids = [r["trial_id"] for r in rows]

if len(ids) != 3 or set(ids) != expected_ids:
    raise RuntimeError("TRIAL IDS INVALID")

if any(r["card_id"] != "NTAG215_02" for r in rows):
    raise RuntimeError("CARD ID MISMATCH")

if any(r["planned_auth0"] != "04" for r in rows):
    raise RuntimeError("PLANNED CONFIGURATION MISMATCH")

if any(r["status"] != "PLANNED" for r in rows):
    raise RuntimeError("UNEXPECTED TRIAL STATUS")

result_fields = [
    "outcome",
    "event_observed",
    "right_censored",
    "ttc_seconds",
    "evidence_path"
]

for row in rows:
    if any((row[field] or "").strip() for field in result_fields):
        raise RuntimeError(
            "PLANNED TRIAL HAS RESULT DATA"
        )

print("EXP-02 DATASET VALIDATION: PASSED")
print("TOTAL PLANNED TRIALS:", len(rows))
print("ACTUAL ATTACK EVENTS: 0")
print("VERIFIED CENSORED TRIALS: 0")
print("AUTHORIZED CONTROL: EXCLUDED FROM ATTACK EVENTS")
print("COX CALIBRATION: NOT READY")
print("DATA COLLECTION STRUCTURE: READY")
print("NO NFC WRITE PERFORMED")

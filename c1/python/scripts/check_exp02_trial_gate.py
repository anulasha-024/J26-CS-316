import csv
import json
from pathlib import Path

dataset = Path("Datasets/exp02_trials.csv")
protocol_file = Path("Datasets/exp02_trial_protocol.json")

if not dataset.is_file() or not protocol_file.is_file():
    raise RuntimeError("REQUIRED FILE MISSING")

with dataset.open(encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

protocol = json.loads(
    protocol_file.read_text(encoding="utf-8-sig")
)

measurement = protocol["measurement"]

if measurement["attacker_tier"] != "T2":
    raise RuntimeError("ATTACKER TIER MISMATCH")

if measurement["observation_window_seconds"] != 180:
    raise RuntimeError("OBSERVATION WINDOW MISMATCH")

expected = {
    "EXP02-T01": "ATTACK",
    "EXP02-T02": "ATTACK",
    "EXP02-T03": "CONTROL"
}

if len(rows) != 3:
    raise RuntimeError("INVALID TRIAL COUNT")

seen = set()

for row in rows:
    tid = row["trial_id"]

    if tid in seen or tid not in expected:
        raise RuntimeError("INVALID OR DUPLICATE TRIAL")

    seen.add(tid)

    if row["trial_role"] != expected[tid]:
        raise RuntimeError("TRIAL ROLE MISMATCH")

    if row["status"] != "PLANNED":
        raise RuntimeError("UNEXPECTED TRIAL STATUS")

    if row["analysis_eligible"] != "NO":
        raise RuntimeError("PREMATURE ANALYSIS ELIGIBILITY")

    for field in (
        "outcome",
        "event_observed",
        "right_censored",
        "ttc_seconds",
        "observed_auth0",
        "observation_window_seconds",
        "evidence_path"
    ):
        if (row.get(field) or "").strip():
            raise RuntimeError(
                f"UNVERIFIED RESULT FOUND: {tid}"
            )

if set(expected) != seen:
    raise RuntimeError("TRIAL IDS MISSING")

print("PROTOCOL CONSISTENCY: PASSED")
print("ATTACKER TIER: T2")
print("OBSERVATION WINDOW: 180 SECONDS")
print("PLANNED ATTACK TRIALS: 2")
print("PLANNED CONTROL TRIALS: 1")
print("UNVERIFIED RESULTS: 0")
print("COX DATASET GATE: PASSED")

safety = protocol["safety"]

if (
    safety["external_backup"] == "PENDING"
    or safety["write_protection"] == "NOT_ENABLED"
):
    print("HARDWARE ATTACK TESTING: NOT READY")
    print("EXTERNAL BACKUP / PROTECTION: PENDING")
else:
    print("HARDWARE SAFETY: REQUIRES LIVE VERIFICATION")

print("NO NFC WRITE PERFORMED")

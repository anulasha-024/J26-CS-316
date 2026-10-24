import csv
import shutil
from pathlib import Path

file = Path("Datasets/exp02_trials.csv")
backup = Path("Datasets/exp02_trials_before_update.csv")

if not file.exists():
    raise RuntimeError("DATASET NOT FOUND")

with file.open("r", encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    fields = list(reader.fieldnames or [])
    rows = list(reader)

expected = {"EXP02-T01", "EXP02-T02", "EXP02-T03"}

if len(rows) != 3 or {
    r["trial_id"] for r in rows
} != expected:
    raise RuntimeError("UNEXPECTED TRIAL DATA")

if any(r["status"] != "PLANNED" for r in rows):
    raise RuntimeError("TRIAL ALREADY STARTED - STOP")

new_columns = [
    "trial_role",
    "observed_auth0",
    "observation_window_seconds",
    "measurement_method",
    "stop_reason",
    "analysis_eligible"
]

for col in new_columns:
    if col not in fields:
        fields.append(col)

for row in rows:
    trial = row["trial_id"]

    row["trial_role"] = (
        "CONTROL" if trial == "EXP02-T03"
        else "ATTACK"
    )

    row["analysis_eligible"] = "NO"

    for col in [
        "observed_auth0",
        "observation_window_seconds",
        "measurement_method",
        "stop_reason"
    ]:
        row.setdefault(col, "")

if not backup.exists():
    shutil.copy2(file, backup)

with file.open("w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("COX DATASET STRUCTURE: UPDATED")
print("ATTACK TRIALS: 2")
print("AUTHORIZED CONTROL TRIALS: 1")
print("ANALYSIS ELIGIBLE TRIALS: 0")
print("ORIGINAL DATA: PRESERVED")
print("NO NFC WRITE PERFORMED")

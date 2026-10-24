import csv
import json
from pathlib import Path

def read_csv(filename):
    with Path(filename).open(
        encoding="utf-8-sig", newline=""
    ) as f:
        return list(csv.DictReader(f))

def flag(value):
    value = str(value or "").strip().lower()
    if value in ("1", "true", "yes", "y"):
        return True
    if value in ("0", "false", "no", "n"):
        return False
    return None

def positive_time(value):
    try:
        number = float(value)
        return number if 0 < number < float("inf") else None
    except (TypeError, ValueError):
        return None

attacks = read_csv("Datasets/attacks.csv")
timing = read_csv("Datasets/automated_timing.csv")
planned = read_csv("Datasets/exp02_trials.csv")

candidate_events = 0
censor_flags = 0
incomplete = 0

print("=== HISTORICAL ATTACK DATA AUDIT ===")

for i, row in enumerate(attacks, 1):
    compromised = flag(row.get("compromised"))
    censored = flag(row.get("censored"))
    ttc = positive_time(row.get("time_to_compromise"))

    if compromised is True and censored is False and ttc:
        label = "EVENT CANDIDATE - EVIDENCE REVIEW NEEDED"
        candidate_events += 1
    elif censored is True and compromised is False:
        label = "CENSOR FLAG - WINDOW REVIEW NEEDED"
        censor_flags += 1
    else:
        label = "INCOMPLETE OR INCONSISTENT"
        incomplete += 1

    print(
        f"Trial {i}: "
        f"Config={row.get('config_id', '')} | "
        f"Tier={row.get('tier', '')} | "
        f"TTC={row.get('time_to_compromise', '')} | "
        f"{label}"
    )

methods = sorted({
    (row.get("measurement_method") or "UNSPECIFIED").strip()
    for row in timing
})

report = {
    "historical_attack_records": len(attacks),
    "event_candidates": candidate_events,
    "unverified_censor_flags": censor_flags,
    "incomplete_or_inconsistent": incomplete,
    "automated_timing_records": len(timing),
    "automated_measurement_methods": methods,
    "planned_exp02_trials": len(planned),
    "confirmed_cox_eligible_from_this_audit": 0,
    "cox_calibration": "NOT_READY"
}

output = Path(
    "results/Reports/N1_Attack_Measurement_Audit.json"
)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps(report, indent=4),
    encoding="utf-8"
)

print("\n=== DATA QUALITY SUMMARY ===")
print("HISTORICAL ATTACK RECORDS:", len(attacks))
print("EVENT CANDIDATES:", candidate_events)
print("UNVERIFIED CENSOR FLAGS:", censor_flags)
print("INCOMPLETE/INCONSISTENT:", incomplete)
print("AUTOMATED TIMING RECORDS:", len(timing))
print("PLANNED EXP-02 TRIALS:", len(planned))
print("COX ELIGIBILITY: REQUIRES EVIDENCE REVIEW")
print("COX CALIBRATION: NOT READY")
print("AUDIT REPORT: SAVED")
print("NO NFC WRITE PERFORMED")

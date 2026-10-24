import json
from pathlib import Path

root = Path("Datasets")
snapshot = json.loads(Path(
    "results/Reports/EXP02_Live_Factor_Snapshot.json"
).read_text(encoding="utf-8"))

protocol = json.loads(
    (root / "exp02_trial_protocol.json").read_text(
        encoding="utf-8"
    )
)

if snapshot["uid"] != "04A3C090310289":
    raise RuntimeError("UID MISMATCH")

if snapshot["auth0"] != "FF" or snapshot["prot"] != 0:
    raise RuntimeError("UNEXPECTED LIVE CONFIGURATION")

if protocol["planned_auth0"] != "04":
    raise RuntimeError("PLANNED AUTH0 MISMATCH")

report = {
    "experiment": "EXP-02",
    "card_id": "NTAG215_02",
    "observed_auth0": snapshot["auth0"],
    "observed_prot": snapshot["prot"],
    "observed_write_protected": False,
    "planned_auth0": protocol["planned_auth0"],
    "planned_prot": protocol["planned_prot"],
    "factor_variation_measured": False,
    "protected_attack_trials_completed": 0,
    "cox_calibration_ready": False
}

output = Path(
    "results/Reports/EXP02_Factor_Variation.json"
)

output.write_text(
    json.dumps(report, indent=4),
    encoding="utf-8"
)

print("OBSERVED CONFIGURATION: UNPROTECTED")
print("PLANNED CONFIGURATION: WRITE PROTECTED")
print("FACTOR VARIATION: NOT YET MEASURED")
print("FACTOR COMPARISON REPORT: SAVED")
print("COX CALIBRATION: NOT READY")
print("NO NFC WRITE PERFORMED")

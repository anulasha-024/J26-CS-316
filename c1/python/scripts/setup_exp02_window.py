import json
from pathlib import Path

file = Path("Datasets/exp02_trial_protocol.json")

if not file.exists():
    raise RuntimeError("PROTOCOL FILE NOT FOUND")

protocol = json.loads(file.read_text(encoding="utf-8-sig"))

if protocol["status"] != "PLANNED":
    raise RuntimeError("PROTOCOL ALREADY ACTIVE")

measurement = protocol["measurement"]

if measurement.get("attacker_tier") not in (
    "TO_BE_DEFINED", "T2"
):
    raise RuntimeError("EXISTING TIER REQUIRES REVIEW")

if measurement.get("observation_window_seconds") not in (
    None, 180
):
    raise RuntimeError("EXISTING WINDOW REQUIRES REVIEW")

measurement["attacker_tier"] = "T2"
measurement["observation_window_seconds"] = 180
measurement["measurement_method"] = (
    "PYTHON_MONOTONIC_TIMER_WITH_READBACK"
)

protocol["protocol_version"] = "EXP02-PILOT-01"
protocol["window_status"] = "PROPOSED_PRE_TRIAL"
protocol["cox_calibration"] = "NOT_READY"

file.write_text(
    json.dumps(protocol, indent=4),
    encoding="utf-8"
)

print("ATTACKER TIER: T2")
print("OBSERVATION WINDOW: 180 SECONDS")
print("TTC MEASUREMENT METHOD: DEFINED")
print("PROTOCOL STATUS: PILOT PREPARATION")
print("ACTUAL ATTACK EVENTS: 0")
print("COX CALIBRATION: NOT READY")
print("NO NFC WRITE PERFORMED")

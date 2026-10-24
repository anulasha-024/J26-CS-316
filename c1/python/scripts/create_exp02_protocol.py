import json
from pathlib import Path

file = Path("Datasets/exp02_trial_protocol.json")

protocol = {
    "experiment": "EXP-02",
    "card_id": "NTAG215_02",
    "planned_auth0": "04",
    "planned_prot": 0,
    "status": "PLANNED",

    "attack_trials": [
        "EXP02-T01",
        "EXP02-T02"
    ],

    "control_trial": "EXP02-T03",

    "measurement": {
        "attacker_tier": "TO_BE_DEFINED",
        "time_origin": "Start of attacker attempt",
        "event": "Unauthorized data modification verified by read-back",
        "time_to_compromise_unit": "seconds",
        "observation_window_seconds": None,
        "measurement_method": "TO_BE_DEFINED"
    },

    "cox_rules": {
        "event_observed_1":
            "Verified unauthorized compromise",

        "event_observed_0":
            "No compromise by the end of a valid predefined observation window",

        "censoring_requirement":
            "Complete observation and documented stopping time",

        "invalid_trial":
            "Interrupted or inconclusive experiment",

        "authorized_control":
            "Exclude from attacker compromise events"
    },

    "safety": {
        "external_backup": "PENDING",
        "write_protection": "NOT_ENABLED",
        "hardware_attack_tests": "NOT_STARTED"
    },

    "cox_calibration": "NOT_READY"
}

if not file.exists():
    file.parent.mkdir(parents=True, exist_ok=True)

    file.write_text(
        json.dumps(protocol, indent=4),
        encoding="utf-8"
    )
    print("ATTACK MEASUREMENT PROTOCOL: CREATED")
else:
    print("ATTACK MEASUREMENT PROTOCOL: ALREADY EXISTS")

with file.open("r", encoding="utf-8") as f:
    saved = json.load(f)

if saved["experiment"] != "EXP-02":
    raise RuntimeError("PROTOCOL EXPERIMENT MISMATCH")

print("TTC MEASUREMENT RULES: DOCUMENTED")
print("COX EVENT RULES: DOCUMENTED")
print("CENSORING RULES: DOCUMENTED")
print("ATTACK TESTING: NOT STARTED")
print("NO NFC WRITE PERFORMED")

import csv
import json
import hashlib
from pathlib import Path

snapshot = Path(
    "results/Reports/EXP02_Live_Factor_Snapshot.json"
)

factors = Path(
    "Datasets/exp02_factor_observations.csv"
)

trials = Path(
    "Datasets/exp02_trials.csv"
)

report = Path(
    "results/Reports/EXP02_Evidence_Audit.json"
)

for file in (snapshot, factors, trials):
    if not file.is_file():
        raise RuntimeError(f"MISSING FILE: {file}")

raw = snapshot.read_bytes()
source = json.loads(raw.decode("utf-8-sig"))

with factors.open(
    encoding="utf-8-sig", newline=""
) as f:
    observations = list(csv.DictReader(f))

with trials.open(
    encoding="utf-8-sig", newline=""
) as f:
    trial_rows = list(csv.DictReader(f))

if len(observations) != 1:
    raise RuntimeError("INVALID FACTOR OBSERVATIONS")

observation = observations[0]

actual_hash = hashlib.sha256(raw).hexdigest()

if observation["evidence_sha256"].lower() != actual_hash:
    raise RuntimeError("EVIDENCE SHA256 MISMATCH")

print("LIVE EVIDENCE HASH: VERIFIED")

if (
    source["uid"] != observation["uid"]
    or observation["uid"] != "04A3C090310289"
    or source["auth0"] != observation["auth0"]
    or int(source["prot"]) != int(observation["prot"])
):
    raise RuntimeError("SECURITY FACTOR MISMATCH")

if (
    observation["auth0"] != "FF"
    or observation["password_enforced"] != "NO"
    or observation["write_protected"] != "NO"
    or observation["security_profile"] != "PRE_PROTECTION"
    or observation["cox_analysis_eligible"] != "NO"
):
    raise RuntimeError("INCORRECT SECURITY STATE")

print("SECURITY FACTOR SEMANTICS: PASSED")

if len(trial_rows) != 3:
    raise RuntimeError("INVALID TRIAL COUNT")

for trial in trial_rows:
    if (
        trial["planned_auth0"] != "04"
        or trial["status"] != "PLANNED"
        or trial["analysis_eligible"] != "NO"
    ):
        raise RuntimeError("TRIAL STATE MISMATCH")

print("PLANNED VS OBSERVED: SEPARATED")

audit = {
    "experiment": "EXP-02",
    "card_id": "NTAG215_02",
    "uid": observation["uid"],
    "evidence_integrity": "VERIFIED",
    "evidence_sha256": actual_hash,
    "observed_auth0": "FF",
    "planned_auth0": "04",
    "password_protection": "DISABLED",
    "planned_trials": 3,
    "cox_eligible_trials": 0,
    "calibration_status": "NOT_READY",
    "nfc_write_performed": False
}

report.parent.mkdir(parents=True, exist_ok=True)

report.write_text(
    json.dumps(audit, indent=4),
    encoding="utf-8"
)

print("OBSERVED PROTECTION: DISABLED")
print("COX ELIGIBLE TRIALS: 0")
print("EVIDENCE AUDIT: SAVED")
print("NO NFC WRITE PERFORMED")

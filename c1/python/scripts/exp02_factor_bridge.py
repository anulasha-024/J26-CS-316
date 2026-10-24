import json
import csv
import hashlib
from pathlib import Path

source = Path(
    "results/Reports/EXP02_Live_Factor_Snapshot.json"
)

output = Path(
    "Datasets/exp02_factor_observations.csv"
)

if not source.is_file():
    raise RuntimeError("LIVE FACTOR SNAPSHOT MISSING")

raw = source.read_bytes()
data = json.loads(raw.decode("utf-8-sig"))

if data.get("uid") != "04A3C090310289":
    raise RuntimeError("CARD UID MISMATCH")

if data.get("source") != "LIVE_FLIPPER_READ":
    raise RuntimeError("UNVERIFIED EVIDENCE SOURCE")

if data.get("auth0") != "FF":
    raise RuntimeError("AUTH0 MISMATCH")

if data.get("prot") != 0:
    raise RuntimeError("PROT MISMATCH")

if data.get("password_protection_enabled") is not False:
    raise RuntimeError("PROTECTION STATE MISMATCH")

if data.get("experiment_status") != "PRE_PROTECTION":
    raise RuntimeError("UNEXPECTED EXPERIMENT STATE")

row = {
    "observation_id": "EXP02-PRE-001",
    "card_id": "NTAG215_02",
    "uid": data["uid"],
    "tag_type": "NTAG215",
    "auth0": data["auth0"],
    "prot": data["prot"],
    "password_configured": "YES",
    "password_enforced": "NO",
    "write_protected": "NO",
    "read_protected": "NO",
    "security_profile": "PRE_PROTECTION",
    "observed_at_utc": data["timestamp_utc"],
    "evidence_path": str(source),
    "evidence_sha256": hashlib.sha256(raw).hexdigest(),
    "cox_analysis_eligible": "NO"
}

output.parent.mkdir(parents=True, exist_ok=True)

if output.exists():
    with output.open(
        encoding="utf-8-sig", newline=""
    ) as f:
        existing = list(csv.DictReader(f))

    if existing != [row]:
        raise RuntimeError(
            "EXISTING FACTOR DATASET DIFFERS - NOT OVERWRITTEN"
        )

    print("SCORING FACTOR DATASET: ALREADY VERIFIED")

else:
    with output.open(
        "w", encoding="utf-8-sig", newline=""
    ) as f:
        writer = csv.DictWriter(
            f, fieldnames=list(row.keys())
        )
        writer.writeheader()
        writer.writerow(row)

    print("SCORING FACTOR DATASET: CREATED")

print("LIVE FACTORS: EXTRACTED")
print("PASSWORD ENFORCEMENT: DISABLED")
print("EVIDENCE SHA256: RECORDED")
print("ACTUAL ATTACK DATA: NOT INCLUDED")
print("COX CALIBRATION: NOT READY")
print("NO NFC WRITE PERFORMED")

import csv
import json
from pathlib import Path

config_file = Path("Datasets/configs.csv")
snapshot_file = Path(
    "results/Reports/EXP02_Live_Factor_Snapshot.json"
)
factor_file = Path(
    "Datasets/exp02_factor_observations.csv"
)

for f in (config_file, snapshot_file, factor_file):
    if not f.is_file():
        raise RuntimeError(f"MISSING FILE: {f}")

with config_file.open(
    encoding="utf-8-sig", newline=""
) as f:
    configs = list(csv.DictReader(f))

with factor_file.open(
    encoding="utf-8-sig", newline=""
) as f:
    factors = list(csv.DictReader(f))

snapshot = json.loads(
    snapshot_file.read_text(encoding="utf-8-sig")
)

matching = [
    r for r in configs
    if r.get("card_instance") == "NTAG215_02"
]

if len(matching) != 1:
    raise RuntimeError("MASTER CONFIG MISSING OR DUPLICATE")

if len(factors) != 1:
    raise RuntimeError("FACTOR RECORD INVALID")

master = matching[0]
factor = factors[0]

if master["ndef_protection"] != "UNPROTECTED":
    raise RuntimeError("MASTER PROTECTION MISMATCH")

if master["auth_type"] != "No authentication":
    raise RuntimeError("MASTER AUTHENTICATION MISMATCH")

if snapshot["auth0"] != "FF" or snapshot["prot"] != 0:
    raise RuntimeError("LIVE FACTOR MISMATCH")

if (
    factor["password_enforced"] != "NO"
    or factor["write_protected"] != "NO"
    or factor["cox_analysis_eligible"] != "NO"
):
    raise RuntimeError("SCORING FACTOR MISMATCH")

print("MASTER CONFIGURATION: VERIFIED")
print("LIVE NFC FACTORS: MATCHED")
print("PASSWORD ENFORCEMENT: DISABLED")
print("FALSE PROTECTION CLASSIFICATION: PREVENTED")
print("COX CALIBRATION: NOT READY")
print("NO DATA MODIFIED")
print("NO NFC WRITE PERFORMED")

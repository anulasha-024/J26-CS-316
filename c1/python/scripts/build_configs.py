from pathlib import Path
import csv

# Project paths
project_root = Path(__file__).resolve().parents[2]

nfc_file = (
    project_root
    / "python"
    / "raw_data"
    / "NTAG215_01_BASELINE.nfc"
)

dataset_folder = project_root / "Datasets"
configs_file = dataset_folder / "configs.csv"

# Check NFC file
if not nfc_file.exists():
    print("ERROR: NFC baseline file not found")
    print(nfc_file)
    raise SystemExit

# Read Flipper NFC file
data = {}

with open(nfc_file, "r", encoding="utf-8", errors="replace") as file:
    for line in file:
        line = line.strip()

        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()

uid = data.get("UID", "UNKNOWN")

# Detect UID length
if uid != "UNKNOWN":
    uid_bytes = uid.split()
    uid_type = f"{len(uid_bytes)}-byte"
else:
    uid_type = "UNKNOWN"

# Create dataset folder if needed
dataset_folder.mkdir(parents=True, exist_ok=True)

fields = [
    "config_id",
    "family",
    "card_instance",
    "uid_type",
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
    "otp_set",
]

baseline_record = {
    "config_id": "NTAG215_01_BASELINE",
    "family": "NTAG215",
    "card_instance": "NTAG215_01",
    "uid_type": uid_type,

    # These security factors will be confirmed by later lab tests
    "uid_writable": "UNKNOWN",
    "auth_type": "UNKNOWN",
    "default_key_present": "UNKNOWN",
    "lock_state": "UNKNOWN",
    "ndef_protection": "UNKNOWN",
    "cve_flag": "UNKNOWN",
    "otp_set": "UNKNOWN",
}

with open(configs_file, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fields)

    writer.writeheader()
    writer.writerow(baseline_record)

print("configs.csv created successfully.")
print(f"Saved to: {configs_file}")
print(f"Card: NTAG215_01")
print(f"UID type: {uid_type}")
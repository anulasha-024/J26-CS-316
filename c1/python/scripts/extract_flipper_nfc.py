from pathlib import Path

# Location of the downloaded Flipper NFC file
nfc_file = (
    Path(__file__).resolve().parent.parent
    / "raw_data"
    / "NTAG215_01_BASELINE.nfc"
)

print("N1 NFC Baseline Parser")
print("----------------------")

if not nfc_file.exists():
    print("ERROR: NFC file not found")
    print("Expected file:")
    print(nfc_file)
    raise SystemExit
data = {}

with open(nfc_file, "r", encoding="utf-8", errors="replace") as file:
    for line in file:
        line = line.strip()

        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()

print(f"File: {nfc_file.name}")
print()

important_fields = [
    "Device type",
    "UID",
    "ATQA",
    "SAK",
    "Mifare version",
    "Pages total",
]

for field in important_fields:
    if field in data:
        print(f"{field}: {data[field]}")

print()
print("File successfully parsed.")
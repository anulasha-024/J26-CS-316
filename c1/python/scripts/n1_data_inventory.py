import csv
from pathlib import Path
from collections import Counter

files = [
    "Datasets/attacks.csv",
    "Datasets/automated_timing.csv",
    "Datasets/exp02_trials.csv"
]

print("=== N1 SCORING DATA INVENTORY ===")

for filename in files:
    path = Path(filename)

    print(f"\nDATASET: {path.name}")

    if not path.is_file():
        print("STATUS: NOT FOUND")
        continue

    with path.open(
        encoding="utf-8-sig",
        newline=""
    ) as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        rows = list(reader)

    print("STATUS: FOUND")
    print("TOTAL RECORDS:", len(rows))
    print("COLUMNS:", ", ".join(columns))

    for field in ("status", "outcome", "event_observed"):
        if field in columns:
            counts = Counter(
                (row.get(field) or "BLANK").strip()
                or "BLANK"
                for row in rows
            )
            print(f"{field.upper()} COUNTS:", dict(counts))

print("\nAUTOMATED USB TIMING IS NOT AUTOMATICALLY TTC")
print("COX CALIBRATION: NOT READY")
print("EXTERNAL BACKUP: PENDING")
print("NO DATA MODIFIED")
print("NO NFC WRITE PERFORMED")

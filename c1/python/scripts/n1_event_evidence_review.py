import csv
import math
from pathlib import Path

source = Path("Datasets/attacks.csv")

output = Path(
    "results/Reports/N1_Historical_Event_Review.csv"
)

def flag(value):
    value = str(value or "").strip().lower()
    if value in ("1", "true", "yes", "y"):
        return True
    if value in ("0", "false", "no", "n"):
        return False
    return None

with source.open(
    encoding="utf-8-sig", newline=""
) as f:
    rows = list(csv.DictReader(f))

reviews = []

for line_number, row in enumerate(rows, start=2):

    try:
        ttc = float(row.get("time_to_compromise") or "")
    except ValueError:
        continue

    if not math.isfinite(ttc) or ttc <= 0:
        continue

    if (
        flag(row.get("compromised")) is True
        and flag(row.get("censored")) is False
    ):
        reviews.append({
            "source_csv_line": line_number,
            "config_id": row.get("config_id", ""),
            "attacker_tier": row.get("tier", ""),
            "repeat_no": row.get("repeat_no", ""),
            "recorded_ttc_seconds": ttc,
            "read_success_recorded": row.get("read_success", ""),
            "write_success_recorded": row.get("write_success", ""),
            "timing_method": "",
            "time_origin_evidence": "",
            "compromise_readback_evidence": "",
            "end_to_end_ttc_verified": "PENDING",
            "event_evidence_verified": "PENDING",
            "analysis_eligible": "NO",
            "review_status": "PENDING"
        })

if not reviews:
    raise RuntimeError("NO EVENT CANDIDATES FOUND")

output.parent.mkdir(parents=True, exist_ok=True)

if output.exists():
    print("EVIDENCE REVIEW FILE: ALREADY EXISTS")
    print("EXISTING FILE: NOT OVERWRITTEN")
else:
    with output.open(
        "w", encoding="utf-8-sig", newline=""
    ) as f:
        writer = csv.DictWriter(
            f, fieldnames=list(reviews[0].keys())
        )
        writer.writeheader()
        writer.writerows(reviews)

    print("EVIDENCE REVIEW FILE: CREATED")

print("EVENT CANDIDATES:", len(reviews))

for review in reviews:
    print(
        f"CSV LINE {review['source_csv_line']}: "
        f"TTC={review['recorded_ttc_seconds']}s | "
        "EVIDENCE=PENDING"
    )

print("COX ELIGIBLE EVENTS: 0")
print("ORIGINAL ATTACK DATA: UNCHANGED")
print("NO NFC WRITE PERFORMED")

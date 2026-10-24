from pathlib import Path
import pandas as pd

project_root = Path(__file__).resolve().parents[2]

scores_folder = project_root / "results" / "Scores"
reports_folder = project_root / "results" / "Reports"

reports_folder.mkdir(parents=True, exist_ok=True)

output_file = reports_folder / "N1_Final_Security_Report.csv"

print("N1 Final Security Report Generator")
print("----------------------------------")

score_files = []

for tier in ["T1", "T2", "T3"]:
    score_file = scores_folder / f"{tier}_scores.csv"

    if score_file.exists():
        score_files.append(score_file)

if not score_files:
    print("Final report cannot be generated yet.")
    print("Reason: no calculated score files are available.")
    print("Real laboratory testing and Cox-derived weights are still required.")
    raise SystemExit

all_results = []

for score_file in score_files:
    data = pd.read_csv(score_file)

    if not data.empty:
        all_results.append(data)

if not all_results:
    print("Final report cannot be generated.")
    print("Reason: score files contain no results.")
    raise SystemExit

final_report = pd.concat(
    all_results,
    ignore_index=True
)

required_columns = [
    "config_id",
    "family",
    "card_instance",
    "tier",
    "risk_score",
    "classification",
]

available_columns = [
    column
    for column in required_columns
    if column in final_report.columns
]

final_report = final_report[available_columns]

final_report.to_csv(
    output_file,
    index=False
)

print()
print("Final report generated successfully.")
print(f"Saved to: {output_file}")
print(f"Total results: {len(final_report)}")
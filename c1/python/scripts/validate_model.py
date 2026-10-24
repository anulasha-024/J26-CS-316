from pathlib import Path
import pandas as pd

project_root = Path(__file__).resolve().parents[2]

attacks_file = project_root / "Datasets" / "attacks.csv"
scores_folder = project_root / "results" / "Scores"
validation_folder = project_root / "results" / "Validation"

validation_folder.mkdir(parents=True, exist_ok=True)

print("N1 Model Validation")
print("-------------------")

# Check real attack-trial data
if not attacks_file.exists():
    print("Validation cannot run yet.")
    print("Reason: attacks.csv does not exist.")
    raise SystemExit

attacks = pd.read_csv(attacks_file)

if attacks.empty:
    print("Validation cannot run yet.")
    print("Reason: no real attack-trial data is available.")
    raise SystemExit

# Check score files
score_files = []

for tier in ["T1", "T2", "T3"]:
    score_file = scores_folder / f"{tier}_scores.csv"

    if score_file.exists():
        score_files.append(score_file)

if not score_files:
    print("Validation cannot run yet.")
    print("Reason: no calculated risk-score files are available.")
    raise SystemExit

print(f"Attack trials available: {len(attacks)}")
print(f"Score files available: {len(score_files)}")

print()
print("Validation data is ready.")

print("Planned validation methods:")
print("1. Spearman correlation")
print("2. Repeatability testing")
print("3. Sensitivity analysis")
print("4. Baseline comparison")
print("5. Leave-One-Family-Out validation")

print()
print("Full validation will run after sufficient real laboratory data is collected.")
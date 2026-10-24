from pathlib import Path
import pandas as pd

project_root = Path(__file__).resolve().parents[2]

configs_file = project_root / "Datasets" / "configs.csv"
attacks_file = project_root / "Datasets" / "attacks.csv"

processed_folder = project_root / "python" / "processed data"
processed_folder.mkdir(parents=True, exist_ok=True)

output_file = processed_folder / "clean_merged_data.csv"

print("N1 Data Cleaning")
print("----------------")

# Check required files
if not configs_file.exists():
    print("ERROR: configs.csv not found")
    raise SystemExit

if not attacks_file.exists():
    print("ERROR: attacks.csv not found")
    raise SystemExit

# Load datasets
configs = pd.read_csv(configs_file)
attacks = pd.read_csv(attacks_file)

print(f"Configs rows: {len(configs)}")
print(f"Attack rows: {len(attacks)}")

# Remove fully empty rows
configs = configs.dropna(how="all")
attacks = attacks.dropna(how="all")

# Check whether attack trials exist
if attacks.empty:
    print()
    print("No attack trial data available yet.")
    print("Hardware testing is still required.")
    print("configs.csv is ready, but merged Cox dataset cannot be created yet.")
    raise SystemExit

# Merge using config_id
merged = attacks.merge(
    configs,
    on="config_id",
    how="left"
)

# Save cleaned dataset
merged.to_csv(output_file, index=False)

print()
print("Data cleaning completed.")
print(f"Saved to: {output_file}")
print(f"Merged rows: {len(merged)}")
from pathlib import Path
import pandas as pd


# --------------------------------------------------
# Project paths
# --------------------------------------------------

project_root = Path(__file__).resolve().parents[2]

configs_file = project_root / "Datasets" / "configs.csv"
attacks_file = project_root / "Datasets" / "attacks.csv"

reports_folder = project_root / "results" / "Reports"
reports_folder.mkdir(parents=True, exist_ok=True)

output_file = reports_folder / "data_readiness_report.txt"


# --------------------------------------------------
# Start
# --------------------------------------------------

print()
print("N1 Real Data Readiness Check")
print("----------------------------")


# --------------------------------------------------
# Check files
# --------------------------------------------------

if not configs_file.exists():
    print("ERROR: configs.csv not found.")
    raise SystemExit

if not attacks_file.exists():
    print("ERROR: attacks.csv not found.")
    raise SystemExit


# --------------------------------------------------
# Load data
# --------------------------------------------------

configs = pd.read_csv(configs_file)
attacks = pd.read_csv(attacks_file)


# --------------------------------------------------
# Convert experimental fields to numeric
# --------------------------------------------------

numeric_columns = [
    "repeat_no",
    "read_success",
    "write_success",
    "emulation_success",
    "compromised",
    "time_to_compromise",
    "censored",
    "attempts",
]

for column in numeric_columns:
    if column in attacks.columns:
        attacks[column] = pd.to_numeric(
            attacks[column],
            errors="coerce"
        )


# --------------------------------------------------
# Basic counts
# --------------------------------------------------

total_trials = len(attacks)

complete_trials = attacks.dropna(
    subset=[
        "compromised",
        "time_to_compromise",
        "censored",
    ]
).copy()

incomplete_trials = total_trials - len(complete_trials)

event_trials = 0
censored_trials = 0

if not complete_trials.empty:
    event_trials = int(
        (complete_trials["censored"] == 0).sum()
    )

    censored_trials = int(
        (complete_trials["censored"] == 1).sum()
    )


# --------------------------------------------------
# Unique configurations / tiers
# --------------------------------------------------

unique_configs = 0
unique_tiers = 0

if "config_id" in complete_trials.columns:
    unique_configs = complete_trials[
        "config_id"
    ].nunique()

if "tier" in complete_trials.columns:
    unique_tiers = complete_trials[
        "tier"
    ].nunique()


# --------------------------------------------------
# Merge with security-factor configuration data
# --------------------------------------------------

merged = attacks.merge(
    configs,
    on="config_id",
    how="left"
)


factor_columns = [
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
]


factor_variation = {}

for factor in factor_columns:

    if factor not in merged.columns:
        factor_variation[factor] = 0
        continue

    values = (
        merged[factor]
        .dropna()
        .astype(str)
        .str.strip()
    )

    values = values[
        ~values.isin(
            [
                "UNKNOWN",
                "Not Applicable",
            ]
        )
    ]

    factor_variation[factor] = values.nunique()


# --------------------------------------------------
# Determine technical readiness
# --------------------------------------------------

blockers = []


if len(complete_trials) < 2:
    blockers.append(
        "Too few complete real trials."
    )


if event_trials == 0:
    blockers.append(
        "No compromised/event trial is available."
    )


if censored_trials == 0:
    blockers.append(
        "No non-compromised/censored trial is available."
    )


if unique_configs < 2:
    blockers.append(
        "Only one complete NFC configuration is available."
    )


no_variation_factors = [
    factor
    for factor, count in factor_variation.items()
    if count < 2
]


if no_variation_factors:
    blockers.append(
        "Security-factor variation is insufficient "
        "for Cox-derived factor weights."
    )


# --------------------------------------------------
# Console report
# --------------------------------------------------

print(f"Total attack trials: {total_trials}")
print(f"Complete trials: {len(complete_trials)}")
print(f"Incomplete trials: {incomplete_trials}")
print(f"Event / compromised trials: {event_trials}")
print(f"Censored / non-compromised trials: {censored_trials}")
print(f"Unique complete configurations: {unique_configs}")
print(f"Unique complete tiers: {unique_tiers}")

print()
print("Security-factor variation:")

for factor, count in factor_variation.items():
    print(
        f"  {factor}: {count} unique applicable value(s)"
    )


print()

if blockers:

    print("STATUS: NOT READY for Cox-derived final weights")

    print()
    print("Current blockers:")

    for blocker in blockers:
        print(f" - {blocker}")

    print()
    print(
        "Do not fabricate missing trials or weights."
    )

else:

    print(
        "STATUS: Basic technical requirements are present."
    )

    print(
        "Statistical adequacy still requires "
        "researcher/supervisor review."
    )


# --------------------------------------------------
# Save text report
# --------------------------------------------------

report_lines = [
    "N1 Real Data Readiness Report",
    "=============================",
    "",
    f"Total attack trials: {total_trials}",
    f"Complete trials: {len(complete_trials)}",
    f"Incomplete trials: {incomplete_trials}",
    f"Event / compromised trials: {event_trials}",
    f"Censored / non-compromised trials: {censored_trials}",
    f"Unique complete configurations: {unique_configs}",
    f"Unique complete tiers: {unique_tiers}",
    "",
    "Security-factor variation:",
]

for factor, count in factor_variation.items():
    report_lines.append(
        f"- {factor}: {count} unique applicable value(s)"
    )


report_lines.append("")

if blockers:

    report_lines.append(
        "STATUS: NOT READY for Cox-derived final weights"
    )

    report_lines.append("")

    report_lines.append("Current blockers:")

    for blocker in blockers:
        report_lines.append(
            f"- {blocker}"
        )

else:

    report_lines.append(
        "STATUS: Basic technical requirements are present."
    )

    report_lines.append(
        "Statistical adequacy still requires "
        "researcher/supervisor review."
    )


output_file.write_text(
    "\n".join(report_lines),
    encoding="utf-8"
)


print()
print(f"Readiness report saved to: {output_file}")
from pathlib import Path
import pandas as pd
from lifelines import CoxPHFitter

project_root = Path(__file__).resolve().parents[2]

processed_file = (
    project_root
    / "python"
    / "processed data"
    / "clean_merged_data.csv"
)

weights_folder = project_root / "results" / "Weights"
weights_folder.mkdir(parents=True, exist_ok=True)

print("N1 Cox Regression Model")
print("-----------------------")

# --------------------------------------------------
# Security factors used in the scoring model
# --------------------------------------------------

factors = [
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
]

factor_maps = {

    "uid_writable": {
        "Fixed UID": 0,
        "Writable UID": 1,
    },

    "auth_type": {
        "AES / 3DES": 0,
        "Password": 0.5,
        "No authentication": 1,
    },

    "default_key_present": {
        "Changed key": 0,
        "Default key present": 1,
    },

    "lock_state": {
        "Fully locked": 0,
        "Partially locked": 0.5,
        "Unlocked": 1,
    },

    "ndef_protection": {
        "Read-only": 0,
        "Read / write": 1,
    },

    "cve_flag": {
        "No known issue": 0,
        "Known vulnerability": 1,
    },
}


# --------------------------------------------------
# Check cleaned dataset
# --------------------------------------------------

if not processed_file.exists():

    print("Cox regression cannot run yet.")
    print("Reason: clean_merged_data.csv does not exist.")
    print("Real hardware attack-trial data is still required.")

    raise SystemExit


data = pd.read_csv(processed_file)

if data.empty:

    print("Cox regression cannot run.")
    print("Reason: cleaned dataset is empty.")

    raise SystemExit


# --------------------------------------------------
# Required columns
# --------------------------------------------------

required_columns = [
    "tier",
    "compromised",
    "time_to_compromise",
    "censored",
] + factors


missing_columns = [
    column
    for column in required_columns
    if column not in data.columns
]

if missing_columns:

    print("Missing required columns:")

    for column in missing_columns:
        print(f"- {column}")

    raise SystemExit


# --------------------------------------------------
# Convert trial fields to numeric
# --------------------------------------------------

numeric_columns = [
    "compromised",
    "time_to_compromise",
    "censored",
]

for column in numeric_columns:

    data[column] = pd.to_numeric(
        data[column],
        errors="coerce"
    )


# Skip incomplete trials without fabricating missing research data
rows_before = len(data)

data = data.dropna(
    subset=[
        "compromised",
        "time_to_compromise",
        "censored",
    ]
).copy()

skipped_rows = rows_before - len(data)

if skipped_rows > 0:
    print(f"INFO: Skipped {skipped_rows} incomplete trial(s).")

if data.empty:
    print("ERROR: No complete real trials available for Cox regression.")
    raise SystemExit

# Cox regression needs both event and censored/non-event outcomes
if data["compromised"].nunique() < 2:
    print(
        "ERROR: Cox regression cannot be fitted yet. "
        "Both compromised and non-compromised/censored outcomes are required."
    )
    print(f"Complete real trials available: {len(data)}")
    raise SystemExit

# --------------------------------------------------
# Check experimental data consistency
# --------------------------------------------------

invalid_trials = data[
    (
        (data["compromised"] == 0)
        &
        (
            (data["censored"] != 1)
            |
            (data["time_to_compromise"] != 1800)
        )
    )
    |
    (
        (data["compromised"] == 1)
        &
        (data["censored"] != 0)
    )
]

if not invalid_trials.empty:

    print("ERROR: Inconsistent trial records detected.")
    print(
        "Check compromised, censored and "
        "time_to_compromise values."
    )

    raise SystemExit


# --------------------------------------------------
# Encode security factors
# --------------------------------------------------

encoded_columns = []

for factor in factors:

    if data[factor].astype(str).str.upper().eq("UNKNOWN").any():

        print("Cox regression cannot run yet.")
        print(f"Reason: {factor} contains UNKNOWN values.")
        print("Complete the real security-factor tests first.")

        raise SystemExit

    encoded_column = f"{factor}_coded"

    data[encoded_column] = data[factor].map(
        factor_maps[factor]
    )

    if data[encoded_column].isna().any():

        invalid_values = (
            data.loc[
                data[encoded_column].isna(),
                factor
            ]
            .astype(str)
            .unique()
        )

        print(f"ERROR: Invalid values in {factor}:")
        print(invalid_values)

        raise SystemExit

    encoded_columns.append(encoded_column)


# --------------------------------------------------
# Fit one Cox model for each attacker tier
# --------------------------------------------------

for tier in ["T1", "T2", "T3"]:

    print()
    print(f"Processing {tier}...")

    tier_data = data[
        data["tier"].astype(str).str.upper() == tier
    ].copy()

    if tier_data.empty:

        print(f"{tier}: No trial data available.")
        continue


    events = int(tier_data["compromised"].sum())
    censored_trials = int(
        (tier_data["compromised"] == 0).sum()
    )

    print(f"Trials: {len(tier_data)}")
    print(f"Compromised events: {events}")
    print(f"Censored trials: {censored_trials}")


    if events == 0:

        print(
            f"{tier}: Cox model cannot be fitted "
            "because no compromise events exist."
        )

        continue


    if censored_trials == 0:

        print(
            f"{tier}: Cox model cannot be fitted "
            "because no censored observations exist."
        )

        continue


    # Only factors with variation can be estimated
    active_factors = []

    for factor in factors:

        encoded_column = f"{factor}_coded"

        if tier_data[encoded_column].nunique() > 1:
            active_factors.append(factor)


    if not active_factors:

        print(
            f"{tier}: No security factors have "
            "enough variation for Cox regression."
        )

        continue


    active_columns = [
        f"{factor}_coded"
        for factor in active_factors
    ]


    fit_columns = (
        active_columns
        + [
            "time_to_compromise",
            "compromised",
        ]
    )


    # If multiple physical cards exist,
    # use card_instance for clustered robust errors
    use_cluster = (
        "card_instance" in tier_data.columns
        and tier_data["card_instance"].nunique() > 1
    )


    if use_cluster:
        fit_columns.append("card_instance")


    fit_data = tier_data[fit_columns].copy()


    # --------------------------------------------------
    # Fit Cox proportional hazards model
    # --------------------------------------------------

    cph = CoxPHFitter()

    try:

        if use_cluster:

            cph.fit(
                fit_data,
                duration_col="time_to_compromise",
                event_col="compromised",
                cluster_col="card_instance",
                robust=True,
            )

        else:

            cph.fit(
                fit_data,
                duration_col="time_to_compromise",
                event_col="compromised",
            )

    except Exception as error:

        print(f"{tier}: Cox regression failed.")
        print(f"Reason: {error}")

        continue


    # --------------------------------------------------
    # Save complete statistical summary
    # --------------------------------------------------

    summary_file = (
        weights_folder
        / f"{tier}_cox_summary.csv"
    )

    cph.summary.to_csv(summary_file)


    # --------------------------------------------------
    # Convert Cox coefficients into risk weights
    #
    # Risk-oriented coding is used:
    # Safe = 0
    # Medium = 0.5
    # Risky = 1
    #
    # Positive coefficients increase compromise hazard.
    # Negative coefficients are not used as positive risk
    # contributions and are therefore set to zero.
    # Positive contributions are normalized to sum to 1.
    # --------------------------------------------------

    result_rows = []

    positive_total = 0

    coefficient_results = {}


    for factor in factors:

        encoded_column = f"{factor}_coded"

        if factor in active_factors:

            coefficient = float(
                cph.params_[encoded_column]
            )

            hazard_ratio = float(
                cph.hazard_ratios_[encoded_column]
            )

            p_value = float(
                cph.summary.loc[
                    encoded_column,
                    "p"
                ]
            )

        else:

            coefficient = 0.0
            hazard_ratio = 1.0
            p_value = float("nan")


        risk_contribution = max(
            coefficient,
            0.0
        )

        positive_total += risk_contribution


        coefficient_results[factor] = {
            "coefficient": coefficient,
            "hazard_ratio": hazard_ratio,
            "p_value": p_value,
            "risk_contribution": risk_contribution,
        }


    if positive_total <= 0:

        print(
            f"{tier}: No positive Cox coefficients "
            "were available to derive risk weights."
        )

        continue


    for factor in factors:

        values = coefficient_results[factor]

        weight = (
            values["risk_contribution"]
            / positive_total
        )

        result_rows.append({

            "factor": factor,

            "coefficient": round(
                values["coefficient"],
                6
            ),

            "hazard_ratio": round(
                values["hazard_ratio"],
                6
            ),

            "p_value": (
                round(values["p_value"], 6)
                if pd.notna(values["p_value"])
                else ""
            ),

            "weight": round(
                weight,
                6
            ),
        })


    weights_file = (
        weights_folder
        / f"{tier}_weights.csv"
    )


    pd.DataFrame(
        result_rows
    ).to_csv(
        weights_file,
        index=False
    )


    print(f"{tier}: Cox model completed.")
    print(f"Weights saved to: {weights_file}")
    print(f"Summary saved to: {summary_file}")


print()
print("Cox regression processing completed.")
from pathlib import Path
import pandas as pd


# --------------------------------------------------
# Project paths
# --------------------------------------------------

project_root = Path(__file__).resolve().parents[2]

configs_file = project_root / "Datasets" / "configs.csv"

weights_folder = project_root / "results" / "Weights"
scores_folder = project_root / "results" / "Scores"

weights_folder.mkdir(parents=True, exist_ok=True)
scores_folder.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# Start
# --------------------------------------------------

print("N1 NFC Risk Score Calculator")
print("----------------------------")


# --------------------------------------------------
# Check configs.csv
# --------------------------------------------------

if not configs_file.exists():
    print("ERROR: configs.csv not found.")
    raise SystemExit


configs = pd.read_csv(configs_file)


# --------------------------------------------------
# Security factors used by N1 scoring model
# --------------------------------------------------

factors = [
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
]


# --------------------------------------------------
# Proposal coding
#
# Safe   = 0
# Medium = 0.5
# Risky  = 1
#
# "Not Applicable" is handled separately and
# excluded from both numerator and denominator.
# --------------------------------------------------

factor_maps = {

    "uid_writable": {
        "Fixed UID": 0,
        "Writable UID": 1,
    },

    "auth_type": {
        "AES / DES": 0,
        "AES/DES": 0,
        "Password": 0.5,
        "No authentication": 1,
    },

    "default_key_present": {
        "Changed key": 0,
        "Default key present": 1,
    },

    "lock_state": {
        "Fully locked": 0,
        "FULLY LOCKED": 0,
        "Partially locked": 0.5,
        "PARTIALLY LOCKED": 0.5,
        "Unlocked": 1,
        "UNLOCKED": 1,
    },

    "ndef_protection": {
        "Read-only": 0,
        "READ-ONLY": 0,
        "Protected": 0.5,
        "Password protected": 0.5,
        "Unprotected": 1,
        "UNPROTECTED": 1,
    },

    "cve_flag": {
        "No": 0,
        "No known CVE": 0,
        "NO": 0,
        "Yes": 1,
        "Known CVE": 1,
        "YES": 1,
    },
}


# --------------------------------------------------
# Classification
# --------------------------------------------------

def classify_score(score):

    if score <= 33:
        return "Low"

    elif score <= 66:
        return "Medium"

    else:
        return "High"


# --------------------------------------------------
# Check required columns
# --------------------------------------------------

required_columns = [
    "config_id",
    "family",
    "card_instance",
] + factors


missing_columns = [
    column
    for column in required_columns
    if column not in configs.columns
]


if missing_columns:
    print(
        "ERROR: Missing required columns in configs.csv:"
    )

    for column in missing_columns:
        print(f" - {column}")

    raise SystemExit


# --------------------------------------------------
# Check for UNKNOWN values
#
# UNKNOWN is not treated as safe/risky.
# Real evidence is required.
#
# Not Applicable is allowed.
# --------------------------------------------------

unknown_found = False

for factor in factors:

    values = (
        configs[factor]
        .fillna("UNKNOWN")
        .astype(str)
        .str.strip()
    )

    unknown_rows = values.str.upper() == "UNKNOWN"

    if unknown_rows.any():

        print()
        print("Risk score cannot be calculated yet.")
        print(
            f"Reason: {factor} still contains UNKNOWN values."
        )
        print(
            "Real laboratory security-factor testing "
            "is required."
        )

        unknown_found = True
        break


if unknown_found:
    raise SystemExit


print("Security factors are available.")


# --------------------------------------------------
# Tier-wise scoring
# --------------------------------------------------

for tier in ["T1", "T2", "T3"]:

    weights_file = (
        weights_folder
        / f"{tier}_weights.csv"
    )


    # ----------------------------------------------
    # Cox-derived weights required
    # ----------------------------------------------

    if not weights_file.exists():

        print()
        print(
            f"{tier}: Cox-derived weights "
            "are not available yet."
        )

        continue


    # ----------------------------------------------
    # Read weights
    # ----------------------------------------------

    weights_df = pd.read_csv(weights_file)


    if not {
        "factor",
        "weight"
    }.issubset(weights_df.columns):

        print(
            f"{tier}: Invalid weights file."
        )

        continue


    # Convert weights to numeric
    weights_df["weight"] = pd.to_numeric(
        weights_df["weight"],
        errors="coerce"
    )


    if weights_df["weight"].isna().any():

        print(
            f"{tier}: Invalid numeric weights."
        )

        continue


    # Build factor -> weight dictionary
    weights = dict(
        zip(
            weights_df["factor"],
            weights_df["weight"]
        )
    )


    # ----------------------------------------------
    # Score each NFC configuration
    # ----------------------------------------------

    results = []


    for _, row in configs.iterrows():

        weighted_sum = 0.0
        maximum_weighted_sum = 0.0

        valid = True


        for factor in factors:

            raw_value = str(
                row[factor]
            ).strip()


            # --------------------------------------
            # Not Applicable
            #
            # Example:
            # NTAG215 does not use MIFARE Classic
            # Key A / Key B.
            #
            # Therefore this factor contributes
            # neither risk nor denominator weight.
            # --------------------------------------

            if raw_value == "Not Applicable":
                continue


            # --------------------------------------
            # Check value exists in mapping
            # --------------------------------------

            if raw_value not in factor_maps[factor]:

                print(
                    f"Unknown value for "
                    f"{factor}: {raw_value}"
                )

                valid = False
                break


            factor_value = (
                factor_maps[factor][raw_value]
            )


            weight = float(
                weights.get(factor, 0)
            )


            weighted_sum += (
                weight * factor_value
            )


            maximum_weighted_sum += weight


        # ------------------------------------------
        # Skip invalid configuration
        # ------------------------------------------

        if not valid:
            continue


        # ------------------------------------------
        # Ensure usable weights exist
        # ------------------------------------------

        if maximum_weighted_sum <= 0:

            print(
                f"{tier}: No usable weights "
                f"for config {row['config_id']}."
            )

            continue


        # ------------------------------------------
        # Risk score
        # ------------------------------------------

        risk_score = (
            weighted_sum
            / maximum_weighted_sum
        ) * 100


        risk_score = round(
            risk_score,
            2
        )


        # ------------------------------------------
        # Save result in memory
        # ------------------------------------------

        results.append(
            {
                "config_id": row["config_id"],
                "family": row["family"],
                "card_instance": row["card_instance"],
                "tier": tier,
                "risk_score": risk_score,
                "classification":
                    classify_score(risk_score),
            }
        )


    # --------------------------------------------------
    # Save tier scores
    # --------------------------------------------------

    if results:

        output_file = (
            scores_folder
            / f"{tier}_scores.csv"
        )


        pd.DataFrame(
            results
        ).to_csv(
            output_file,
            index=False
        )


        print()
        print(
            f"{tier}: Scores saved to "
            f"{output_file}"
        )


        for result in results:

            print(
                f"{result['config_id']} | "
                f"Score: {result['risk_score']} | "
                f"Classification: "
                f"{result['classification']}"
            )


    else:

        print()
        print(
            f"{tier}: No scores generated."
        )


# --------------------------------------------------
# Finish
# --------------------------------------------------

print()
print("N1 scoring process finished.")
"""Build one feature row per card/session."""

import json

import pandas as pd

import config
from preprocessing import load_data, validate_csv


# Keep identifiers and collection information for tracing and splitting only.
METADATA_COLUMNS = [
    "physical_source_id", "session_id", "source_class", "card_family", "run_id",
    "logger_version", "acquisition_tier", "dataset_stage", "timing_kind", "timing_unit",
]
FEATURE_NAMES = [
    "observation_count", "successful_timing_count", "success_rate", "timeout_rate",
    "error_rate", "skipped_rate", "mean_us", "median_us", "std_us", "iqr_us",
    "min_us", "max_us", "cv",
]


def get_command_features(rows, command):
    """Failed timings are excluded from timing statistics."""
    elapsed = pd.to_numeric(rows["elapsed_us"], errors="coerce")
    elapsed = elapsed.replace([float("inf"), -float("inf")], float("nan"))
    timings = elapsed[(rows["status"] == "success") & (elapsed > 0)]
    values = {}
    values["observation_count"] = len(rows)
    values["successful_timing_count"] = len(timings)
    for status in config.STATUSES:
        values[status + "_rate"] = (rows["status"] == status).mean()
    # pandas returns NaN (saved as blank) when a statistic is unavailable.
    values["mean_us"] = timings.mean()
    values["median_us"] = timings.median()
    values["std_us"] = timings.std()
    values["iqr_us"] = timings.quantile(0.75) - timings.quantile(0.25)
    values["min_us"] = timings.min()
    values["max_us"] = timings.max()
    values["cv"] = float("nan")
    if len(timings) >= 2 and values["mean_us"] > 0:
        values["cv"] = values["std_us"] / values["mean_us"]
    features = {}
    for name in FEATURE_NAMES:
        features[command.lower() + "_" + name] = values[name]
    return features


def get_feature_columns():
    """Return an explicit list of allowed model features for each family."""
    family_features = {}
    for family, commands in config.FAMILY_COMMANDS.items():
        family_features[family] = []
        for command in commands:
            for name in FEATURE_NAMES:
                family_features[family].append(command.lower() + "_" + name)
    return family_features


def build_session_features(data):
    """Combine command summaries into one row per physical session."""
    fingerprints = []
    for (source, session), session_rows in data.groupby(["physical_source_id", "session_id"]):
        fingerprint = {}
        for column in METADATA_COLUMNS:
            fingerprint[column] = session_rows[column].iloc[0]
        family = fingerprint["card_family"]
        for command in config.FAMILY_COMMANDS[family]:
            command_rows = session_rows[session_rows["command"] == command]
            if command_rows.empty:
                raise ValueError(f"Missing {command} in source {source}, session {session}.")
            fingerprint.update(get_command_features(command_rows, command))
        fingerprints.append(fingerprint)
    columns = list(METADATA_COLUMNS)
    for names in get_feature_columns().values():
        columns.extend(names)
    # Columns for another family stay blank: that command was not applicable.
    return pd.DataFrame(fingerprints).reindex(columns=columns)


def main():
    """Validate the current CSV, then save features and their documented schema."""
    report = validate_csv(config.RAW_DATA_PATH)
    if report["errors"]:
        print("Feature extraction stopped. Resolve the validation errors first:")
        for message in report["errors"]:
            print(message)
        return 2
    for message in report["warnings"]:
        print("WARNING:", message)
    data = load_data(config.RAW_DATA_PATH)
    features = build_session_features(data)
    config.SESSION_FEATURES_PATH.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(config.SESSION_FEATURES_PATH, index=False, na_rep="")
    schema = {
        "schema_version": "pilot_timing_outcomes_v1",
        "input_sha256": report["input_sha256"],
        "fingerprint_rows": len(features),
        "metadata_columns": METADATA_COLUMNS,
        "features_by_family": get_feature_columns(),
        "timing_rule": "Positive successful timings only; std uses sample standard deviation.",
        "missing_rule": "Blank means unavailable or not applicable; no imputation here.",
        "scope": "Timing and command outcomes; response_hex, UID and identity values are excluded.",
    }
    with open(config.FEATURE_SCHEMA_PATH, "w", encoding="utf-8") as file:
        json.dump(schema, file, indent=2)
    print("Session feature rows:", len(features))
    print("Saved:", config.SESSION_FEATURES_PATH)
    print("Saved:", config.FEATURE_SCHEMA_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

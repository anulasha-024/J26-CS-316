"""Check the C2 pilot CSV and save a report. No ML training happens here."""

import csv
import hashlib
import json
import math
from pathlib import Path

import pandas as pd

import config


def load_data(file_path):
    """Read the CSV as text. Keep original CSV line numbers for the report."""
    rows = []
    line_numbers = []
    with open(file_path, newline="", encoding="utf-8-sig") as file:
        reader = csv.reader(file)
        columns = next(reader, [])
        if not columns or len(columns) != len(set(columns)):
            raise ValueError("The CSV header is empty or has repeated column names.")
        for row in reader:
            if not row:
                continue
            if len(row) != len(columns):
                raise ValueError(f"Wrong number of values at CSV line {reader.line_num}.")
            rows.append(row)
            line_numbers.append(reader.line_num)
    data = pd.DataFrame(rows, columns=columns, index=line_numbers)
    for column in data.columns:
        data[column] = data[column].str.strip()
    return data


def check_values(data, errors, warnings):
    """Check labels, measurements, missing values and repeated observations."""
    for column in config.REQUIRED_VALUES:
        missing = data[data[column] == ""]
        if not missing.empty:
            errors.append(f"Blank {column}: CSV lines {missing.index.tolist()[:5]}.")

    allowed_values = dict(config.PILOT_METADATA)
    allowed_values["source_class"] = config.SOURCE_CLASSES
    allowed_values["status"] = config.STATUSES
    allowed_values["card_family"] = list(config.FAMILY_COMMANDS)
    for column, allowed in allowed_values.items():
        if isinstance(allowed, str):
            allowed = [allowed]
        if not data[column].isin(allowed).all():
            errors.append(f"Unexpected value in {column}.")
    for column in config.BOOLEAN_COLUMNS:
        if not data[column].isin(["", "0", "1"]).all():
            errors.append(f"{column} must be blank, 0 or 1.")
    if (data["session_complete"] == "0").any():
        warnings.append("Some observations belong to an incomplete acquisition.")

    for column in config.NUMERIC_COLUMNS:
        for line, text in data[column].items():
            if text == "":
                continue
            try:
                number = float(text)
                valid = math.isfinite(number) and number >= 0
                if column in config.INTEGER_COLUMNS:
                    valid = valid and number.is_integer()
                if column in ["trial_no", "ticks_per_us", "collection_timestamp"]:
                    valid = valid and number > 0
                if not valid:
                    raise ValueError
            except (ValueError, OverflowError):
                errors.append(f"Invalid {column} at CSV line {line}.")

    elapsed = pd.to_numeric(data["elapsed_us"], errors="coerce")
    bad_timing = data[(data["status"] == "success") & ~(elapsed > 0)]
    if not bad_timing.empty:
        errors.append(f"Successful commands need positive timings: {bad_timing.index.tolist()[:5]}.")
    if data.duplicated().any():
        errors.append("Exact duplicate observations found.")
    keys = ["physical_source_id", "session_id", "trial_no", "command", "parameter"]
    if data.duplicated(subset=keys).any():
        errors.append("Repeated source/session/trial/command/parameter keys found.")

    placeholder_count = 0
    for response in data["response_hex"]:
        if response == "":
            continue
        try:
            bytes.fromhex(response)
        except ValueError:
            placeholder_count += 1
    if placeholder_count > 0:
        warnings.append(f"{placeholder_count} response fields need review: incomplete hex or markers.")


def check_sessions(data, errors, warnings):
    """Check card labels and the expected 50 trials of each family command."""
    for source, card_rows in data.groupby("physical_source_id"):
        for column in ["source_class", "card_family"]:
            if card_rows[column].nunique() != 1:
                errors.append(f"Source {source} has conflicting {column} values.")
    for column in ["session_id", "run_id"]:
        for identifier, rows in data.groupby(column):
            if rows["physical_source_id"].nunique() > 1:
                warnings.append(f"{column} {identifier} is shared by multiple sources.")

    for (source, session), rows in data.groupby(["physical_source_id", "session_id"]):
        family = rows["card_family"].iloc[0]
        if family not in config.FAMILY_COMMANDS:
            continue
        commands = config.FAMILY_COMMANDS[family]
        complete = len(rows) == config.EXPECTED_TRIALS * len(commands)
        for command in commands:
            command_rows = rows[rows["command"] == command]
            trials = pd.to_numeric(command_rows["trial_no"], errors="coerce")
            expected = list(range(1, config.EXPECTED_TRIALS + 1))
            if sorted(trials.dropna().tolist()) != expected:
                complete = False
        if not complete:
            errors.append(f"Check {source}, session {session}: {len(rows)} rows, first CSV line {rows.index[0]}.")
        for column in ["run_id", "logger_version", "timing_kind", "timing_unit", "acquisition_tier", "dataset_stage"]:
            if rows[column].nunique() != 1:
                errors.append(f"Mixed {column} in source {source}, session {session}.")


def validate_csv(file_path):
    """Load the data, run checks and return a report dictionary."""
    file_path = Path(file_path)
    report = {"report_schema_version": "2.0", "status": "FAIL", "summary": {}, "errors": [], "warnings": []}
    report["scope"] = "Core pilot checks. Verify logger timing, response encoding, collection days and physical inventory separately."
    errors = report["errors"]
    warnings = report["warnings"]
    try:
        data = load_data(file_path)
        for column in config.EXPECTED_COLUMNS:
            if column not in data.columns:
                errors.append(f"Missing column: {column}.")
        if data.empty:
            errors.append("The CSV contains no observations.")
        if errors:
            return report
        check_values(data, errors, warnings)
        check_sessions(data, errors, warnings)
        report["input_sha256"] = hashlib.sha256(file_path.read_bytes()).hexdigest()
        report["summary"] = {
            "observation_rows": len(data),
            "physical_source_ids": int(data["physical_source_id"].nunique()),
            "source_session_groups": data.groupby(["physical_source_id", "session_id"]).ngroups,
            "class_rows": data["source_class"].value_counts().to_dict(),
            "family_rows": data["card_family"].value_counts().to_dict(),
        }
        if not errors:
            report["status"] = "PASS_WITH_WARNINGS" if warnings else "PASS"
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        errors.append(str(error))
    return report


def main():
    """Run the checks and save the result in results/data_validation.json."""
    if config.RAW_DATA_PATH.resolve() == config.VALIDATION_REPORT_PATH.resolve():
        print("The input CSV and output report must have different paths.")
        return 2
    report = validate_csv(config.RAW_DATA_PATH)
    config.VALIDATION_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(config.VALIDATION_REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
    print("Validation:", report["status"])
    print("Summary:", report["summary"])
    for message in report["errors"]:
        print("ERROR:", message)
    for message in report["warnings"]:
        print("WARNING:", message)
    print("Report saved to:", config.VALIDATION_REPORT_PATH)
    if report["errors"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""List incorrect validation predictions and their features. No model training."""

import hashlib

import joblib
import pandas as pd

import config
from evaluation import evaluate_family, load_validation_data
from feature_extraction import get_feature_columns


def find_errors(validation, manifest):
    """Predict validation labels with the saved models, then keep the mistakes."""
    all_predictions = []
    for family in config.FAMILY_COMMANDS:
        name = family.lower().replace(" ", "_") + "_rf.joblib"
        path = config.MODEL_DIR / name
        bundle = joblib.load(path)
        rows = validation[validation["card_family"] == family]
        metrics, predictions = evaluate_family(rows, bundle, family, manifest)
        predictions["model_version"] = bundle["metadata"]["model_version"]
        predictions["model_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        all_predictions.append(predictions)
    predictions = pd.concat(all_predictions, ignore_index=True)
    errors = predictions[predictions["actual_class"] != predictions["predicted_class"]].copy()

    # Add measured features so we can inspect patterns after identifying cases.
    keys = ["physical_source_id", "session_id", "card_family"]
    feature_columns = []
    for columns in get_feature_columns().values():
        feature_columns.extend(columns)
    details = validation[keys + feature_columns]
    errors = errors.merge(details, on=keys, validate="one_to_one")
    error_types = []
    for actual_class in errors["actual_class"]:
        if actual_class == "Clone":
            error_types.append("missed_clone")
        else:
            error_types.append("genuine_false_alarm")
    errors["error_type"] = error_types
    return errors


def main():
    """Save the incorrect sessions and a summary grouped by physical source."""
    try:
        validation, manifest = load_validation_data()
        errors = find_errors(validation, manifest)
    except (OSError, ValueError, KeyError) as error:
        print("Error analysis stopped:", error)
        return 2
    config.EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    path = config.EVALUATION_DIR / "validation_error_cases.csv"
    errors.to_csv(path, index=False, na_rep="")
    print("Incorrect validation sessions:", len(errors))
    print("Physical sources with errors:", errors["physical_source_id"].nunique())
    columns = ["card_family", "physical_source_id", "session_id", "actual_class", "predicted_class", "error_type"]
    if errors.empty:
        print("No incorrect predictions were found for these inputs and models.")
    else:
        print(errors[columns].to_string(index=False))
    counts = errors.groupby(["card_family", "physical_source_id", "error_type"]).size()
    counts = counts.reset_index(name="incorrect_sessions")
    counts.to_csv(config.EVALUATION_DIR / "validation_errors_by_source.csv", index=False)
    print("Saved error cases and their features to:", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

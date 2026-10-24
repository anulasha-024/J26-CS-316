"""Train and save a first Random Forest model for each NFC card family."""

from datetime import datetime, timezone
import hashlib
import json
import sys

import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

import config
from feature_extraction import get_feature_columns


def load_training_data():
    """Check the saved inputs and source separation before reading training features."""
    with open(config.FEATURE_SCHEMA_PATH, encoding="utf-8") as file:
        schema = json.load(file)
    with open(config.SPLIT_DIR / "split_manifest.json", encoding="utf-8") as file:
        manifest = json.load(file)
    raw_hash = hashlib.sha256(config.RAW_DATA_PATH.read_bytes()).hexdigest()
    feature_hash = hashlib.sha256(config.SESSION_FEATURES_PATH.read_bytes()).hexdigest()
    if raw_hash != manifest["input_sha256"] or raw_hash != schema["input_sha256"]:
        raise ValueError("The raw CSV differs from the saved feature/split inputs.")
    if feature_hash != manifest["session_features_sha256"]:
        raise ValueError("Session features changed after the splits were created.")
    if schema["schema_version"] != manifest["feature_schema_version"]:
        raise ValueError("The feature schema version differs from the split manifest.")

    seen_sources = set()
    for name in ["train", "validation", "test"]:
        # Only source IDs are read from validation/test files for this audit.
        ids = pd.read_csv(config.SPLIT_DIR / (name + ".csv"),
                          usecols=["physical_source_id"], dtype=str, keep_default_na=False)
        sources = set(ids["physical_source_id"])
        if "" in sources or not sources or seen_sources.intersection(sources):
            raise ValueError(f"Blank, absent or overlapping physical sources in {name}.")
        seen_sources.update(sources)

    train = pd.read_csv(config.SPLIT_DIR / "train.csv", dtype=str, keep_default_na=False)
    reference = pd.read_csv(config.SESSION_FEATURES_PATH, dtype=str, keep_default_na=False)
    if seen_sources != set(reference["physical_source_id"]):
        raise ValueError("Split sources do not match the saved session features.")
    if not train["split"].eq("train").all():
        raise ValueError("The training file has incorrect split labels.")
    expected = reference[reference["physical_source_id"].isin(train["physical_source_id"])]
    keys = ["physical_source_id", "session_id"]
    expected = expected.sort_values(keys).reset_index(drop=True)
    actual = train.drop(columns="split").sort_values(keys).reset_index(drop=True)
    if not actual.equals(expected):
        raise ValueError("Training rows differ from the saved session features.")
    return train, schema, manifest


def train_family_model(rows, family, schema):
    """Select numeric features, fit missing-value handling, then train the forest."""
    columns = schema["features_by_family"][family]
    if columns != get_feature_columns()[family]:
        raise ValueError("Unexpected feature list. Use the documented family features.")
    X_train = pd.DataFrame()
    for column in columns:
        X_train[column] = pd.to_numeric(rows[column], errors="raise")
    if X_train.isin([float("inf"), -float("inf")]).any().any():
        raise ValueError(f"Infinite feature values in {family}.")
    # Remove features that have no measured training values. Record this choice.
    usable_columns = []
    for column in columns:
        if X_train[column].notna().any():
            usable_columns.append(column)
    X_train = X_train[usable_columns]
    y_train = rows["source_class"]
    if not usable_columns or set(y_train) != set(config.SOURCE_CLASSES):
        raise ValueError(f"Usable features and both classes are required for {family}.")

    forest = RandomForestClassifier(
        n_estimators=config.RF_TREES, min_samples_leaf=2,
        class_weight="balanced", random_state=config.RANDOM_SEED, n_jobs=-1,
    )
    # The imputer learns medians from training data and adds missingness flags.
    model = Pipeline([("imputer", SimpleImputer(strategy="median", add_indicator=True)),
                      ("classifier", forest)])
    model.fit(X_train, y_train)  # This line performs the actual learning.
    metadata = {
        "model_version": "pilot_rf_v1",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "card_family": family,
        "feature_columns": usable_columns,
        "original_feature_columns": columns,
        "training_session_rows": len(rows),
        "training_source_ids": sorted(rows["physical_source_id"].unique().tolist()),
        "training_class_rows": y_train.value_counts().to_dict(),
        "settings": forest.get_params(),
        "python_version": sys.version.split()[0],
        "pandas_version": pd.__version__, "sklearn_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "calibrated": False, "unknown_rejection": False, "emulator_trained": False,
    }
    return {"pipeline": model, "metadata": metadata}


def main():
    """Fit both family models and save their pipelines and version information."""
    if config.MODEL_DIR.exists() and any(config.MODEL_DIR.iterdir()):
        print("This baseline model folder already contains files. Keep it versioned.")
        return 2
    try:
        train, schema, manifest = load_training_data()
        models = []
        for family in config.FAMILY_COMMANDS:
            rows = train[train["card_family"] == family]
            bundle = train_family_model(rows, family, schema)
            bundle["metadata"]["split_manifest"] = manifest
            bundle["metadata"]["train_csv_sha256"] = hashlib.sha256(
                (config.SPLIT_DIR / "train.csv").read_bytes()).hexdigest()
            models.append(bundle)
    except (OSError, ValueError, KeyError) as error:
        print("Training stopped:", error)
        return 2
    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    for bundle in models:
        metadata = bundle["metadata"]
        name = metadata["card_family"].lower().replace(" ", "_") + "_rf"
        joblib.dump(bundle, config.MODEL_DIR / (name + ".joblib"))
        with open(config.MODEL_DIR / (name + ".json"), "w", encoding="utf-8") as file:
            json.dump(metadata, file, indent=2)
        print(f"Trained {metadata['card_family']}: {metadata['training_session_rows']} sessions")
    print("Saved models to:", config.MODEL_DIR)
    print("Next: evaluate on validation data. Final test metrics are not computed here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

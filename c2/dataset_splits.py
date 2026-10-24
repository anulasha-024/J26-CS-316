"""Separate physical cards into training, validation and test sets. No ML training."""

import hashlib
import json

import pandas as pd
from sklearn.model_selection import train_test_split

import config


def make_source_assignments(features):
    """Split a table of unique physical cards, never the repeated session rows."""
    columns = ["physical_source_id", "source_class", "card_family", "session_id"]
    for column in columns:
        if column not in features.columns or features[column].eq("").any():
            raise ValueError(f"Missing column or blank values: {column}.")
    if features.empty:
        raise ValueError("The feature table is empty.")
    if features.duplicated(["physical_source_id", "session_id"]).any():
        raise ValueError("Repeated source/session fingerprints found.")
    for source, rows in features.groupby("physical_source_id"):
        if rows["source_class"].nunique() != 1 or rows["card_family"].nunique() != 1:
            raise ValueError(f"Source {source} has inconsistent class or family labels.")

    source_columns = ["physical_source_id", "source_class", "card_family"]
    sources = features[source_columns].drop_duplicates()
    sources = sources.sort_values(source_columns).reset_index(drop=True)
    assignments = []
    for family, family_sources in sources.groupby("card_family"):
        if family not in config.FAMILY_COMMANDS:
            raise ValueError(f"Unexpected card family: {family}.")
        if set(family_sources["source_class"]) != set(config.SOURCE_CLASSES):
            raise ValueError(f"Both Genuine and Clone sources are required for {family}.")
        # Reserve about 20% of unique cards for the final test.
        development, test = train_test_split(
            family_sources, test_size=0.20, random_state=config.RANDOM_SEED,
            stratify=family_sources["source_class"],
        )
        # 25% of the remaining 80% gives about 20% for validation.
        train, validation = train_test_split(
            development, test_size=0.25, random_state=config.RANDOM_SEED,
            stratify=development["source_class"],
        )
        for name, rows in [("train", train), ("validation", validation), ("test", test)]:
            if set(rows["source_class"]) != set(config.SOURCE_CLASSES):
                raise ValueError(f"Too few sources for both classes in {family}, {name}.")
            rows = rows.copy()
            rows["split"] = name
            assignments.append(rows)
    assignments = pd.concat(assignments, ignore_index=True)
    if assignments["physical_source_id"].duplicated().any():
        raise ValueError("A physical source appears in more than one split.")
    return assignments.sort_values("physical_source_id").reset_index(drop=True)


def attach_splits(features, assignments):
    """Give every session the split assigned to its physical card."""
    keys = ["physical_source_id", "split"]
    result = features.merge(assignments[keys], on="physical_source_id", validate="many_to_one")
    if len(result) != len(features):
        raise ValueError("Some sessions do not have a source assignment.")
    if result.groupby("physical_source_id")["split"].nunique().max() != 1:
        raise ValueError("Sessions of the same card overlap between splits.")
    return result


def main():
    """Check feature provenance, then save frozen source and session splits."""
    if not config.SESSION_FEATURES_PATH.is_file() or not config.FEATURE_SCHEMA_PATH.is_file():
        print("Run python feature_extraction.py first to create both feature files.")
        return 2
    if config.SPLIT_DIR.exists() and any(config.SPLIT_DIR.iterdir()):
        print("The splits folder already contains files. Keep existing assignments frozen.")
        return 2
    try:
        with open(config.FEATURE_SCHEMA_PATH, encoding="utf-8") as file:
            schema = json.load(file)
        schema_version = schema["schema_version"]
        raw_hash = hashlib.sha256(config.RAW_DATA_PATH.read_bytes()).hexdigest()
        if schema["input_sha256"] != raw_hash:
            raise ValueError("The raw CSV changed. Rebuild the session features first.")
        features = pd.read_csv(config.SESSION_FEATURES_PATH, dtype=str, keep_default_na=False)
        if len(features) != schema["fingerprint_rows"]:
            raise ValueError("Feature row count differs from the feature schema.")
        assignments = make_source_assignments(features)
        sessions = attach_splits(features, assignments)
        feature_hash = hashlib.sha256(config.SESSION_FEATURES_PATH.read_bytes()).hexdigest()
    except (OSError, ValueError, KeyError) as error:
        print("Split creation stopped:", error)
        return 2

    config.SPLIT_DIR.mkdir(parents=True, exist_ok=True)
    assignments.to_csv(config.SPLIT_DIR / "source_assignments.csv", index=False)
    for name in ["train", "validation", "test"]:
        rows = sessions[sessions["split"] == name]
        rows.to_csv(config.SPLIT_DIR / (name + ".csv"), index=False)
        source_count = rows["physical_source_id"].nunique()
        print(f"{name}: {source_count} physical sources, {len(rows)} session rows")
    manifest = {
        "input_sha256": raw_hash,
        "session_features_sha256": feature_hash,
        "feature_schema_version": schema_version,
        "random_seed": config.RANDOM_SEED,
        "split_unit": "physical_source_id",
        "target_source_proportions": {"train": 0.60, "validation": 0.20, "test": 0.20},
        "rule": "Within-family, class-stratified unique sources; all sessions follow their source.",
    }
    with open(config.SPLIT_DIR / "split_manifest.json", "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)
    print("Source overlap: 0. Saved to:", config.SPLIT_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

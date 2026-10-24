"""Evaluate saved models on validation sessions. No training or final test scoring."""

import hashlib
import json

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

import config
from feature_extraction import get_feature_columns
from training import load_training_data


def calculate_metrics(actual, predicted):
    """Rows of the confusion matrix are actual classes; columns are predictions."""
    labels = ["Genuine", "Clone"]
    if len(actual) == 0 or len(actual) != len(predicted):
        raise ValueError("Actual and predicted labels must have equal, nonzero lengths.")
    if not set(actual).issubset(labels) or not set(predicted).issubset(labels):
        raise ValueError("This baseline supports Genuine and Clone labels only.")
    matrix = confusion_matrix(actual, predicted, labels=labels)
    clone_total = int(matrix[1].sum())
    genuine_total = int(matrix[0].sum())
    false_accepts = int(matrix[1, 0])  # Actual Clone predicted as Genuine.
    false_rejects = int(matrix[0, 1])  # Actual Genuine predicted as Clone.
    far = None
    frr = None
    if clone_total > 0:
        far = false_accepts / clone_total
    if genuine_total > 0:
        frr = false_rejects / genuine_total
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "classification_report": classification_report(
            actual, predicted, labels=labels, output_dict=True, zero_division=0),
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix.tolist(),
        "clone_false_acceptance": {"count": false_accepts, "denominator": clone_total, "rate": far},
        "genuine_false_rejection": {"count": false_rejects, "denominator": genuine_total, "rate": frr},
    }


def load_validation_data():
    """Reuse the input/source audit, then check validation rows against saved features."""
    train, schema, manifest = load_training_data()
    rows = pd.read_csv(config.SPLIT_DIR / "validation.csv", dtype=str, keep_default_na=False)
    reference = pd.read_csv(config.SESSION_FEATURES_PATH, dtype=str, keep_default_na=False)
    if not rows["split"].eq("validation").all():
        raise ValueError("Incorrect split labels in validation.csv.")
    expected = reference[reference["physical_source_id"].isin(rows["physical_source_id"])]
    keys = ["physical_source_id", "session_id"]
    expected = expected.sort_values(keys).reset_index(drop=True)
    actual = rows.drop(columns="split").sort_values(keys).reset_index(drop=True)
    if not actual.equals(expected):
        raise ValueError("Validation rows differ from the saved session features.")
    return rows, manifest


def evaluate_family(rows, bundle, family, manifest):
    """Use the saved imputer and forest to predict; never call fit here."""
    metadata = bundle["metadata"]
    if metadata["card_family"] != family or metadata["split_manifest"] != manifest:
        raise ValueError("Model family or training provenance does not match the inputs.")
    train_hash = hashlib.sha256((config.SPLIT_DIR / "train.csv").read_bytes()).hexdigest()
    if metadata["train_csv_sha256"] != train_hash:
        raise ValueError("The training file changed after model fitting.")
    if set(rows["physical_source_id"]).intersection(metadata["training_source_ids"]):
        raise ValueError("Validation sources overlap the model's training sources.")
    columns = metadata["feature_columns"]
    allowed = get_feature_columns()[family]
    if not columns or not set(columns).issubset(allowed):
        raise ValueError("The saved model has an unexpected feature list.")
    X = pd.DataFrame()
    for column in columns:
        X[column] = pd.to_numeric(rows[column], errors="raise")
    if X.isin([float("inf"), -float("inf")]).any().any():
        raise ValueError("Infinite validation feature values found.")
    predicted = bundle["pipeline"].predict(X)
    metrics = calculate_metrics(rows["source_class"], predicted)
    predictions = rows[["physical_source_id", "session_id", "card_family", "source_class"]].copy()
    predictions = predictions.rename(columns={"source_class": "actual_class"})
    predictions["predicted_class"] = predicted
    predictions["correct"] = predictions["actual_class"] == predictions["predicted_class"]
    return metrics, predictions


def main():
    """Evaluate both families, print results and save auditable validation outputs."""
    results = []
    try:
        validation, manifest = load_validation_data()
        for family in config.FAMILY_COMMANDS:
            name = family.lower().replace(" ", "_")
            model_path = config.MODEL_DIR / (name + "_rf.joblib")
            bundle = joblib.load(model_path)
            rows = validation[validation["card_family"] == family]
            if rows.empty:
                raise ValueError(f"No validation sessions for {family}.")
            metrics, predictions = evaluate_family(rows, bundle, family, manifest)
            metrics["card_family"] = family
            metrics["model_version"] = bundle["metadata"]["model_version"]
            metrics["validation_sessions"] = len(rows)
            metrics["validation_sources"] = int(rows["physical_source_id"].nunique())
            metrics["model_sha256"] = hashlib.sha256(model_path.read_bytes()).hexdigest()
            metrics["validation_csv_sha256"] = hashlib.sha256(
                (config.SPLIT_DIR / "validation.csv").read_bytes()).hexdigest()
            metrics["split_manifest"] = manifest
            metrics["scope"] = "Session-level closed-set pilot validation; no calibration or UNKNOWN."
            results.append((name, metrics, predictions))
    except (OSError, ValueError, KeyError) as error:
        print("Evaluation stopped:", error)
        return 2

    config.EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    summary = []
    for name, metrics, predictions in results:
        with open(config.EVALUATION_DIR / (name + "_metrics.json"), "w", encoding="utf-8") as file:
            json.dump(metrics, file, indent=2, allow_nan=False)
        predictions.to_csv(config.EVALUATION_DIR / (name + "_predictions.csv"), index=False)
        labels = metrics["confusion_matrix_labels"]
        matrix = pd.DataFrame(metrics["confusion_matrix"], index=labels, columns=labels)
        matrix.to_csv(config.EVALUATION_DIR / (name + "_confusion_matrix.csv"), index_label="actual_class")
        report = metrics["classification_report"]
        summary.append({"card_family": metrics["card_family"], "sessions": metrics["validation_sessions"],
                        "sources": metrics["validation_sources"], "accuracy": metrics["accuracy"],
                        "macro_f1": report["macro avg"]["f1-score"],
                        "clone_false_acceptance_rate": metrics["clone_false_acceptance"]["rate"],
                        "genuine_false_rejection_rate": metrics["genuine_false_rejection"]["rate"]})
        print(f"\n{metrics['card_family']} - validation accuracy: {metrics['accuracy']:.1%}")
        for label in labels:
            scores = report[label]
            print(f"{label}: precision={scores['precision']:.3f}, recall={scores['recall']:.3f}, F1={scores['f1-score']:.3f}")
        print("Confusion matrix: rows=actual, columns=predicted\n", matrix)
        for key in ["clone_false_acceptance", "genuine_false_rejection"]:
            counts = metrics[key]
            rate = "N/A" if counts["rate"] is None else f"{counts['rate']:.1%}"
            print(f"{key}: {counts['count']}/{counts['denominator']} ({rate})")
    pd.DataFrame(summary).to_csv(config.EVALUATION_DIR / "validation_summary.csv", index=False)
    print("Saved validation results to:", config.EVALUATION_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

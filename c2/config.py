"""Shared settings for the C2 pilot."""

from pathlib import Path

# Find the folder containing this Python file.
C2_DIR = Path(__file__).resolve().parent
# The / operator joins folder names when we use Path.
RAW_DATA_PATH = C2_DIR / "data" / "raw" / "RF_Data_Set.csv"
VALIDATION_REPORT_PATH = C2_DIR / "results" / "data_validation.json"
SESSION_FEATURES_PATH = C2_DIR / "data" / "processed" / "session_features.csv"
FEATURE_SCHEMA_PATH = C2_DIR / "data" / "processed" / "feature_schema.json"
SPLIT_DIR = C2_DIR / "data" / "splits"
MODEL_DIR = C2_DIR / "models" / "pilot_rf_v1"
EVALUATION_DIR = C2_DIR / "results" / "pilot_rf_v1_validation"
RANDOM_SEED = 42  # Used later to make model experiments repeatable.
RF_TREES = 200  # Number of decision trees in the first baseline.

# Column names that must appear in the CSV header.
EXPECTED_COLUMNS = [
    "logger_version", "card_family", "trial_no", "command", "parameter",
    "timing_kind", "cycles", "ticks_per_us", "elapsed_us", "status",
    "error_code", "response_bits", "response_hex", "retry_count", "uid",
    "atqa", "sak", "timer_overhead_cycles", "activation_errors",
    "session_complete", "identity_mismatch", "physical_source_id", "run_id",
    "acquisition_tier", "dataset_stage", "timing_unit", "uid_len",
    "expected_uid_match", "payload_match", "startup_activation_errors",
    "post_activation_errors", "sequence_variant", "source_class", "session_id",
    "collection_timestamp", "identity_check_mode", "payload_reference_mode",
]

# These columns must also have a value in every observation.
# elapsed_us is excluded because skipped commands can have a blank timing.
REQUIRED_VALUES = [
    "logger_version", "card_family", "trial_no", "command", "timing_kind",
    "cycles", "ticks_per_us", "status", "physical_source_id", "run_id",
    "acquisition_tier", "dataset_stage", "timing_unit", "source_class",
    "session_id", "collection_timestamp", "session_complete",
]

SOURCE_CLASSES = ["Genuine", "Clone"]
STATUSES = ["success", "timeout", "error", "skipped"]
# A dictionary connects each card family to its two measured commands.
FAMILY_COMMANDS = {
    "MIFARE Classic 1K": ["AUTH_FULL", "READ_BLOCK"],
    "NTAG215": ["GET_VERSION", "READ"],
}
# Pilot assumption: each session contains 50 trials of each command.
# Confirm this against the collection protocol before changing it.
EXPECTED_TRIALS = 50

NUMERIC_COLUMNS = [
    "trial_no", "cycles", "ticks_per_us", "elapsed_us", "response_bits",
    "retry_count", "timer_overhead_cycles", "activation_errors", "uid_len",
    "startup_activation_errors", "post_activation_errors", "collection_timestamp",
]
# These measurements are counts, so decimal values are not allowed.
INTEGER_COLUMNS = [
    "trial_no", "cycles", "ticks_per_us", "response_bits", "retry_count",
    "timer_overhead_cycles", "activation_errors", "uid_len",
    "startup_activation_errors", "post_activation_errors",
]
BOOLEAN_COLUMNS = [
    "session_complete", "identity_mismatch", "expected_uid_match", "payload_match",
]

# This validator is for the supplied A2 pilot, not a future Proxmark3 dataset.
PILOT_METADATA = {
    "acquisition_tier": "A2",
    "dataset_stage": "PILOT",
    "timing_kind": "software_transaction_latency",
    "timing_unit": "us",
}


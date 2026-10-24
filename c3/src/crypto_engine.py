from pathlib import Path
import hashlib
import hmac
import json
import os


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SECRETS_DIR = PROJECT_ROOT / "secrets"

HMAC_KEY_FILE = SECRETS_DIR / "n3_hmac_key.bin"


# --------------------------------------------------
# CREATE / LOAD SECRET HMAC KEY
# --------------------------------------------------

def load_hmac_key():
    """
    Load the N3 HMAC secret key.

    If the key does not exist,
    generate one secure 256-bit key.
    """

    SECRETS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if not HMAC_KEY_FILE.exists():

        # 32 bytes = 256 bits
        key = os.urandom(32)

        HMAC_KEY_FILE.write_bytes(key)

    key = HMAC_KEY_FILE.read_bytes()

    if len(key) != 32:

        raise ValueError(
            "Invalid N3 HMAC secret key."
        )

    return key


# --------------------------------------------------
# NORMALIZE DATA BEFORE HMAC
# --------------------------------------------------

def normalize_for_hmac(value):
    """
    Convert data into a stable JSON-compatible form.

    Dictionary keys are converted to strings so
    HMAC generation and verification use exactly
    the same representation.
    """

    if isinstance(value, dict):

        return {
            str(key): normalize_for_hmac(item)
            for key, item in value.items()
        }

    if isinstance(value, list):

        return [
            normalize_for_hmac(item)
            for item in value
        ]

    return value


# --------------------------------------------------
# PREPARE BASELINE DATA FOR HMAC
# --------------------------------------------------

def baseline_to_bytes(baseline):
    """
    Convert baseline content into one stable
    byte representation before calculating HMAC.
    """

    # Do not include the HMAC value itself
    payload = {
        key: value
        for key, value in baseline.items()
        if key != "baseline_hmac"
    }

    # Important:
    # Normalize integer/string dictionary keys
    payload = normalize_for_hmac(
        payload
    )

    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return canonical_json.encode(
        "utf-8"
    )


# --------------------------------------------------
# GENERATE BASELINE HMAC
# --------------------------------------------------

def generate_baseline_hmac(baseline):
    """
    Generate HMAC-SHA256 for baseline data.
    """

    secret_key = load_hmac_key()

    baseline_bytes = baseline_to_bytes(
        baseline
    )

    digest = hmac.new(
        secret_key,
        baseline_bytes,
        hashlib.sha256
    )

    return digest.hexdigest()


# --------------------------------------------------
# PROTECT TRUSTED BASELINE
# --------------------------------------------------

def protect_baseline(baseline):
    """
    Add HMAC-SHA256 protection
    to a trusted baseline.
    """

    protected_baseline = dict(
        baseline
    )

    protected_baseline[
        "hmac_algorithm"
    ] = "HMAC-SHA256"

    protected_baseline[
        "baseline_hmac"
    ] = generate_baseline_hmac(
        protected_baseline
    )

    return protected_baseline


# --------------------------------------------------
# VERIFY TRUSTED BASELINE HMAC
# --------------------------------------------------

def verify_baseline_hmac(baseline):
    """
    Verify that the stored trusted baseline
    has not been modified.
    """

    stored_hmac = baseline.get(
        "baseline_hmac"
    )

    algorithm = baseline.get(
        "hmac_algorithm"
    )

    if not stored_hmac:
        return False

    if algorithm != "HMAC-SHA256":
        return False

    calculated_hmac = generate_baseline_hmac(
        baseline
    )

    return hmac.compare_digest(
        stored_hmac,
        calculated_hmac
    )
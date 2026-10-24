from pathlib import Path
from datetime import datetime, timezone
import json
import re

from crypto_engine import (
    protect_baseline,
    verify_baseline_hmac,
)


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BASELINES_DIR = PROJECT_ROOT / "baselines"


# --------------------------------------------------
# NORMALIZE BASELINE IDENTITY
# --------------------------------------------------

def normalize_baseline_identity(card_identity):
    """
    Convert card-family / card-type text into
    one safe baseline identity.

    Examples:

    NTAG215
        -> NTAG215

    MIFARE Classic 1K
        -> MIFARE_CLASSIC_1K

    MIFARE_CLASSIC_1K
        -> MIFARE_CLASSIC_1K
    """

    if card_identity is None:
        return None

    value = str(
        card_identity
    ).strip()

    if not value:
        return None

    upper_value = value.upper()


    # --------------------------------------------------
    # KNOWN CARD FAMILIES
    # --------------------------------------------------

    if upper_value == "NTAG215":
        return "NTAG215"

    if upper_value in {
        "MIFARE CLASSIC 1K",
        "MIFARE_CLASSIC_1K",
    }:
        return "MIFARE_CLASSIC_1K"


    # --------------------------------------------------
    # GENERIC SAFE FALLBACK
    # --------------------------------------------------

    safe_value = re.sub(
        r"[^A-Z0-9]+",
        "_",
        upper_value
    )

    safe_value = safe_value.strip(
        "_"
    )

    return safe_value


# --------------------------------------------------
# GET BASELINE IDENTITY FROM CARD INFO
# --------------------------------------------------

def get_baseline_identity_from_card_info(
    card_info
):
    """
    Prefer the N3 card family as the baseline
    filename identity.

    Fall back to card_type for compatibility
    with older NTAG baselines.
    """

    card_family = card_info.get(
        "card_family"
    )

    card_type = card_info.get(
        "card_type"
    )

    identity = (
        card_family
        or card_type
    )

    return normalize_baseline_identity(
        identity
    )


# --------------------------------------------------
# BUILD TRUSTED BASELINE
# --------------------------------------------------

def build_baseline(
    canonical_scan,
    source_file,
    version=1
):
    """
    Build a trusted baseline from a validated
    canonical NFC enrollment or authorized
    update scan.

    Supports family-aware memory evidence:

    NTAG215
        -> memory_pages

    MIFARE Classic 1K
        -> memory_blocks

    Default version is V1.
    Authorized updates can later create
    V2, V3, etc.
    """

    card_info = canonical_scan[
        "card_info"
    ]

    uid = card_info.get(
        "uid"
    )

    card_type = card_info.get(
        "card_type"
    )

    card_family = card_info.get(
        "card_family"
    )

    baseline_identity = (
        get_baseline_identity_from_card_info(
            card_info
        )
    )


    # --------------------------------------------------
    # VALIDATE IDENTITY
    # --------------------------------------------------

    if not uid:
        raise ValueError(
            "Cannot create baseline: "
            "UID is missing."
        )

    if not card_type:
        raise ValueError(
            "Cannot create baseline: "
            "card type is missing."
        )

    if not baseline_identity:
        raise ValueError(
            "Cannot create baseline: "
            "card family identity is missing."
        )

    if (
        not isinstance(version, int)
        or version < 1
    ):
        raise ValueError(
            "Baseline version must be "
            "a positive integer."
        )


    # --------------------------------------------------
    # MEMORY EVIDENCE
    # --------------------------------------------------

    memory_pages = canonical_scan.get(
        "memory_pages",
        {}
    )

    memory_blocks = canonical_scan.get(
        "memory_blocks",
        {}
    )


    # --------------------------------------------------
    # BUILD BASELINE
    # --------------------------------------------------

    baseline = {

        # ----------------------------------------------
        # BASELINE METADATA
        # ----------------------------------------------

        "baseline_version":
            version,

        "enrollment_time_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "source_file":
            Path(
                source_file
            ).name,

        # Safe identity used for baseline lookup
        "baseline_identity":
            baseline_identity,

        # Family information
        "card_family":
            card_family,

        # ----------------------------------------------
        # CARD INFORMATION
        # ----------------------------------------------

        "card_info":
            card_info,

        # ----------------------------------------------
        # FAMILY-AWARE RAW MEMORY
        # ----------------------------------------------

        # NTAG215
        "memory_pages":
            memory_pages,

        # MIFARE Classic 1K
        "memory_blocks":
            memory_blocks,

        # ----------------------------------------------
        # APPLICATION EVIDENCE
        # ----------------------------------------------

        "ndef_evidence":
            canonical_scan.get(
                "ndef_evidence"
            ),

        # ----------------------------------------------
        # SECURITY-STATE EVIDENCE
        # ----------------------------------------------

        "security_state":
            canonical_scan.get(
                "security_state"
            ),
    }

    return baseline


# --------------------------------------------------
# CREATE BASELINE FILE PATH
# --------------------------------------------------

def make_baseline_path_from_identity(
    card_type,
    uid,
    version=1
):
    """
    Create baseline filename using
    normalized card family/type, UID,
    and baseline version.

    Existing NTAG example:

    NTAG215_04B3D4C4310289_V1.json

    MIFARE example:

    MIFARE_CLASSIC_1K_A7D99D5F_V1.json

    The card_type argument is kept for
    compatibility with existing code.
    It may contain either card type or
    N3 card family.
    """

    safe_identity = (
        normalize_baseline_identity(
            card_type
        )
    )

    if not safe_identity:
        raise ValueError(
            "Cannot create baseline path: "
            "card identity is missing."
        )

    if not uid:
        raise ValueError(
            "Cannot create baseline path: "
            "UID is missing."
        )

    if (
        not isinstance(version, int)
        or version < 1
    ):
        raise ValueError(
            "Baseline version must be "
            "a positive integer."
        )


    safe_uid = (
        str(uid)
        .replace(" ", "")
        .upper()
    )


    filename = (
        f"{safe_identity}_"
        f"{safe_uid}_"
        f"V{version}.json"
    )

    return (
        BASELINES_DIR
        / filename
    )


def make_baseline_path(
    baseline
):
    """
    Create baseline file path from
    stored baseline information.
    """

    card_info = baseline.get(
        "card_info",
        {}
    )

    baseline_identity = baseline.get(
        "baseline_identity"
    )

    if not baseline_identity:

        baseline_identity = (
            get_baseline_identity_from_card_info(
                card_info
            )
        )


    uid = card_info.get(
        "uid"
    )

    version = baseline[
        "baseline_version"
    ]


    return (
        make_baseline_path_from_identity(
            baseline_identity,
            uid,
            version
        )
    )


# --------------------------------------------------
# SAVE TRUSTED BASELINE
# --------------------------------------------------

def save_baseline(
    baseline
):
    """
    Protect baseline using HMAC-SHA256
    and save it as JSON.

    Existing baseline versions are never
    overwritten.
    """

    BASELINES_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    baseline_path = (
        make_baseline_path(
            baseline
        )
    )


    # --------------------------------------------------
    # DO NOT OVERWRITE EXISTING BASELINE VERSION
    # --------------------------------------------------

    if baseline_path.exists():

        raise FileExistsError(
            "Trusted baseline version "
            "already exists for this "
            "NFC tag."
        )


    # --------------------------------------------------
    # ADD HMAC PROTECTION
    # --------------------------------------------------

    protected_baseline = (
        protect_baseline(
            baseline
        )
    )


    # --------------------------------------------------
    # SAVE PROTECTED BASELINE
    # --------------------------------------------------

    with baseline_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            protected_baseline,
            file,
            indent=4,
            sort_keys=True
        )


    return baseline_path


# --------------------------------------------------
# LOAD AND VERIFY STORED BASELINE
# --------------------------------------------------

def load_baseline(
    card_type,
    uid,
    version=1
):
    """
    Load a stored trusted baseline and verify
    its HMAC before allowing it to be used.

    card_type may contain:

    - NTAG215
    - MIFARE Classic 1K
    - MIFARE_CLASSIC_1K

    A specific baseline version can be loaded.
    """

    baseline_path = (
        make_baseline_path_from_identity(
            card_type,
            uid,
            version
        )
    )


    # --------------------------------------------------
    # CHECK WHETHER BASELINE EXISTS
    # --------------------------------------------------

    if not baseline_path.exists():

        raise FileNotFoundError(
            "Trusted baseline was not found "
            "for this NFC tag."
        )


    # --------------------------------------------------
    # LOAD JSON BASELINE
    # --------------------------------------------------

    with baseline_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        baseline = json.load(
            file
        )


    # --------------------------------------------------
    # VERIFY BASELINE HMAC
    # --------------------------------------------------

    if not verify_baseline_hmac(
        baseline
    ):

        raise ValueError(
            "BASELINE INTEGRITY FAILURE: "
            "Stored baseline HMAC is invalid."
        )


    return (
        baseline,
        baseline_path
    )
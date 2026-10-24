from pathlib import Path
import json
import re

from baseline_manager import (
    normalize_baseline_identity,
)


# --------------------------------------------------
# N3 BASELINE PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BASELINES_DIR = PROJECT_ROOT / "baselines"

ARCHIVE_DIR = BASELINES_DIR / "archive"


# --------------------------------------------------
# NORMALIZE CARD TYPE / FAMILY
# --------------------------------------------------

def normalize_card_type(card_type):
    """
    Normalize the card type or card family using
    the same naming rule as baseline_manager.py.

    Examples:

    NTAG215
        -> NTAG215

    MIFARE Classic 1K
        -> MIFARE_CLASSIC_1K

    MIFARE_CLASSIC_1K
        -> MIFARE_CLASSIC_1K
    """

    if not card_type:
        raise ValueError(
            "Card type is missing."
        )

    normalized = normalize_baseline_identity(
        card_type
    )

    if not normalized:
        raise ValueError(
            "Card type could not be normalized."
        )

    return normalized


# --------------------------------------------------
# NORMALIZE UID
# --------------------------------------------------

def normalize_uid(uid):
    """
    Remove spaces and separators from the UID
    so it matches the baseline filename format.

    Example:

    A7 D9 9D 5F
        -> A7D99D5F
    """

    if not uid:
        raise ValueError(
            "UID is missing."
        )

    return (
        str(uid)
        .strip()
        .upper()
        .replace(" ", "")
        .replace(":", "")
        .replace("-", "")
    )


# --------------------------------------------------
# BUILD BASELINE FILE PREFIX
# --------------------------------------------------

def build_baseline_prefix(
    card_type,
    uid
):
    """
    Build the baseline filename prefix.

    NTAG example:

    NTAG215_04B3D4C4310289

    MIFARE example:

    MIFARE_CLASSIC_1K_A7D99D5F
    """

    normalized_card_type = (
        normalize_card_type(
            card_type
        )
    )

    normalized_uid = (
        normalize_uid(
            uid
        )
    )

    return (
        f"{normalized_card_type}_"
        f"{normalized_uid}"
    )


# --------------------------------------------------
# ACTIVE BASELINE POINTER PATH
# --------------------------------------------------

def get_active_baseline_pointer_path(
    card_type,
    uid
):
    """
    Return the per-card ACTIVE baseline pointer path.

    The pointer is scoped by:

    card family + UID

    Example:

    MIFARE_CLASSIC_1K_A7D99D5F_ACTIVE.json
    """

    BASELINES_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    prefix = build_baseline_prefix(
        card_type,
        uid
    )

    return (
        BASELINES_DIR
        / f"{prefix}_ACTIVE.json"
    )


# --------------------------------------------------
# FIND EXISTING BASELINE VERSIONS
# --------------------------------------------------

def get_existing_baseline_versions(
    card_type,
    uid
):
    """
    Find all baseline versions stored
    for one NFC tag.

    Example:

    V1 only
        -> [1]

    V1, V2, V3
        -> [1, 2, 3]

    The lookup is based on:

    card family + UID
    """

    BASELINES_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    prefix = build_baseline_prefix(
        card_type,
        uid
    )

    pattern = re.compile(
        rf"^{re.escape(prefix)}_V(\d+)\.json$"
    )

    versions = []


    # --------------------------------------------------
    # SEARCH BASELINE DIRECTORY
    # --------------------------------------------------

    for file_path in BASELINES_DIR.glob(
        f"{prefix}_V*.json"
    ):

        match = pattern.fullmatch(
            file_path.name
        )

        if not match:
            continue

        version = int(
            match.group(1)
        )

        versions.append(
            version
        )


    # --------------------------------------------------
    # REMOVE DUPLICATES AND SORT
    # --------------------------------------------------

    versions = sorted(
        set(versions)
    )

    return versions


# --------------------------------------------------
# GET LATEST BASELINE VERSION
# --------------------------------------------------

def get_latest_baseline_version(
    card_type,
    uid
):
    """
    Return the highest existing baseline version.

    IMPORTANT:

    This function represents baseline VERSION HISTORY,
    not the explicitly selected trusted ACTIVE version.

    It is used for:

    - finding the highest stored version
    - calculating the next baseline version
    - preserving version history

    Examples:

    []        -> None
    [1]       -> 1
    [1, 2]    -> 2
    [1, 2, 3] -> 3
    """

    versions = (
        get_existing_baseline_versions(
            card_type,
            uid
        )
    )

    if not versions:
        return None

    return max(
        versions
    )


# --------------------------------------------------
# GET NEXT BASELINE VERSION
# --------------------------------------------------

def get_next_baseline_version(
    card_type,
    uid
):
    """
    Calculate the next baseline version using
    the highest existing stored version.

    This is intentionally independent from the
    ACTIVE baseline pointer.

    Examples:

    no baseline
        -> V1

    stored V1
        -> V2

    stored V1 and V2
        -> V3

    Even if ACTIVE = V1 and V2 already exists,
    the next version is still V3.
    """

    latest_version = (
        get_latest_baseline_version(
            card_type,
            uid
        )
    )

    if latest_version is None:
        return 1

    return latest_version + 1


# --------------------------------------------------
# SET ACTIVE BASELINE VERSION
# --------------------------------------------------

def set_active_baseline_version(
    card_type,
    uid,
    version
):
    """
    Explicitly select which baseline version is
    trusted for normal verification.

    The selection is scoped by:

    card family + UID

    Example:

    stored versions:
        V1, V2

    active version:
        V1

    VERIFY should compare against V1.

    Version history is not deleted or overwritten.
    """

    normalized_card_type = (
        normalize_card_type(
            card_type
        )
    )

    normalized_uid = (
        normalize_uid(
            uid
        )
    )

    try:
        version = int(
            version
        )
    except (
        TypeError,
        ValueError
    ):
        raise ValueError(
            "Active baseline version must be an integer."
        )

    if version < 1:
        raise ValueError(
            "Active baseline version must be "
            "greater than or equal to 1."
        )

    versions = (
        get_existing_baseline_versions(
            normalized_card_type,
            normalized_uid
        )
    )

    if version not in versions:
        raise ValueError(
            f"Baseline V{version} does not exist "
            f"for {normalized_card_type} "
            f"UID {normalized_uid}."
        )

    pointer_path = (
        get_active_baseline_pointer_path(
            normalized_card_type,
            normalized_uid
        )
    )

    pointer_data = {
        "card_family":
            normalized_card_type,

        "uid":
            normalized_uid,

        "active_version":
            version,
    }

    with pointer_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            pointer_data,
            file,
            indent=2
        )

    return pointer_path


# --------------------------------------------------
# GET ACTIVE BASELINE VERSION
# --------------------------------------------------

def get_active_baseline_version(
    card_type,
    uid
):
    """
    Return the trusted baseline version that should
    be used for normal verification.

    BACKWARD COMPATIBILITY:

    If no ACTIVE pointer exists for the card,
    N3 uses the highest existing baseline version,
    preserving the previous behavior.

    Example:

    stored:
        V1, V2

    no ACTIVE pointer:
        -> V2

    ACTIVE pointer = V1:
        -> V1
    """

    normalized_card_type = (
        normalize_card_type(
            card_type
        )
    )

    normalized_uid = (
        normalize_uid(
            uid
        )
    )

    pointer_path = (
        get_active_baseline_pointer_path(
            normalized_card_type,
            normalized_uid
        )
    )


    # --------------------------------------------------
    # BACKWARD-COMPATIBLE FALLBACK
    # --------------------------------------------------

    if not pointer_path.exists():

        return (
            get_latest_baseline_version(
                normalized_card_type,
                normalized_uid
            )
        )


    # --------------------------------------------------
    # LOAD ACTIVE POINTER
    # --------------------------------------------------

    try:

        with pointer_path.open(
            "r",
            encoding="utf-8"
        ) as file:

            pointer_data = (
                json.load(
                    file
                )
            )

    except (
        OSError,
        json.JSONDecodeError
    ) as exc:

        raise ValueError(
            "Active baseline pointer could not "
            "be read."
        ) from exc


    # --------------------------------------------------
    # VALIDATE POINTER CONTENT
    # --------------------------------------------------

    pointer_family = (
        normalize_card_type(
            pointer_data.get(
                "card_family"
            )
        )
    )

    pointer_uid = (
        normalize_uid(
            pointer_data.get(
                "uid"
            )
        )
    )

    if (
        pointer_family
        != normalized_card_type
    ):
        raise ValueError(
            "Active baseline pointer card family "
            "does not match the requested card."
        )

    if (
        pointer_uid
        != normalized_uid
    ):
        raise ValueError(
            "Active baseline pointer UID does not "
            "match the requested card."
        )

    try:

        active_version = int(
            pointer_data[
                "active_version"
            ]
        )

    except (
        KeyError,
        TypeError,
        ValueError
    ) as exc:

        raise ValueError(
            "Active baseline pointer contains "
            "an invalid active_version."
        ) from exc


    # --------------------------------------------------
    # CONFIRM ACTIVE VERSION EXISTS
    # --------------------------------------------------

    versions = (
        get_existing_baseline_versions(
            normalized_card_type,
            normalized_uid
        )
    )

    if active_version not in versions:

        raise ValueError(
            "Active baseline pointer references "
            f"V{active_version}, but that baseline "
            "version does not exist."
        )

    return active_version
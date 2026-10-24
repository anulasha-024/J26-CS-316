from baseline_manager import (
    build_baseline,
    save_baseline,
    load_baseline,
)

from baseline_version_manager import (
    get_latest_baseline_version,
    get_next_baseline_version,
)


# --------------------------------------------------
# N3 AUTHORIZED BASELINE UPDATE
# --------------------------------------------------

def create_authorized_baseline_update(
    canonical_scan,
    source_file,
):
    """
    Create the next trusted baseline version
    after an explicitly authorized NFC update.

    Important:
    This function must only be called by an
    authorized update workflow.
    """

    # --------------------------------------------------
    # GET CARD IDENTITY
    # --------------------------------------------------

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    card_type = card_info.get(
        "card_type"
    )

    uid = card_info.get(
        "uid"
    )

    if not card_type:
        raise ValueError(
            "Authorized update failed: "
            "card type is missing."
        )

    if not uid:
        raise ValueError(
            "Authorized update failed: "
            "UID is missing."
        )


    # --------------------------------------------------
    # FIND CURRENT TRUSTED VERSION
    # --------------------------------------------------

    latest_version = (
        get_latest_baseline_version(
            card_type,
            uid
        )
    )

    if latest_version is None:
        raise FileNotFoundError(
            "Authorized update failed: "
            "no existing trusted baseline "
            "was found for this NFC tag."
        )


    # --------------------------------------------------
    # LOAD AND VERIFY CURRENT TRUSTED BASELINE
    # --------------------------------------------------

    current_baseline, current_baseline_path = (
        load_baseline(
            card_type,
            uid,
            version=latest_version
        )
    )


    # --------------------------------------------------
    # CHECK CARD IDENTITY
    # --------------------------------------------------

    trusted_card_info = current_baseline.get(
        "card_info",
        {}
    )

    trusted_card_type = trusted_card_info.get(
        "card_type"
    )

    trusted_uid = trusted_card_info.get(
        "uid"
    )

    if card_type != trusted_card_type:
        raise ValueError(
            "Authorized update rejected: "
            "card type does not match the "
            "trusted baseline."
        )

    if uid != trusted_uid:
        raise ValueError(
            "Authorized update rejected: "
            "UID does not match the "
            "trusted baseline."
        )


    # --------------------------------------------------
    # CALCULATE NEXT BASELINE VERSION
    # --------------------------------------------------

    next_version = (
        get_next_baseline_version(
            card_type,
            uid
        )
    )


    # --------------------------------------------------
    # BUILD NEW TRUSTED BASELINE
    # --------------------------------------------------

    new_baseline = build_baseline(
        canonical_scan,
        source_file,
        version=next_version
    )


    # --------------------------------------------------
    # SAVE NEW HMAC-PROTECTED BASELINE
    # --------------------------------------------------

    new_baseline_path = save_baseline(
        new_baseline
    )


    # --------------------------------------------------
    # RETURN UPDATE INFORMATION
    # --------------------------------------------------

    return {
        "card_type": card_type,
        "uid": uid,

        "previous_version":
            latest_version,

        "new_version":
            next_version,

        "previous_baseline_path":
            current_baseline_path,

        "new_baseline_path":
            new_baseline_path,
    }
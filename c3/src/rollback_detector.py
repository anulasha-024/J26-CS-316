from baseline_manager import load_baseline

from baseline_version_manager import (
    get_existing_baseline_versions,
)

from verifier import (
    verify_raw_memory,
    verify_ndef_application,
    verify_security_state,
)


# --------------------------------------------------
# CHECK WHETHER ALL REQUIRED LAYERS MATCH
# --------------------------------------------------

def all_required_layers_match(
    raw_memory_result,
    ndef_result,
    security_result,
):
    """
    Return True only when all three required
    N3 verification layers match a baseline.
    """

    return (
        raw_memory_result.get("status") == "MATCH"
        and ndef_result.get("status") == "MATCH"
        and security_result.get("status") == "MATCH"
    )


# --------------------------------------------------
# DETECT ROLLBACK TO A VERSION OLDER THAN ACTIVE
# --------------------------------------------------

def detect_rollback(
    canonical_scan,
    card_type,
    uid,
    active_baseline_version,
):
    """
    Check whether the current NFC state exactly matches
    a baseline version older than the currently ACTIVE
    trusted baseline.

    Important distinction:

    active_baseline_version
        = baseline currently trusted for verification

    stored baseline versions
        = historical baseline versions retained by N3

    Example:

        Stored:
            V1
            V2

        ACTIVE:
            V2

        Current card:
            exactly matches V1

        Result:
            ROLLBACK

    Another example:

        Stored:
            V1
            V2

        ACTIVE:
            V1

        Current card:
            exactly matches V2

        Result:
            NOT rollback

        Reason:
            V2 is newer than the currently active
            trusted baseline. It is simply a state
            that differs from V1.
    """

    # --------------------------------------------------
    # STEP 1: GET ALL STORED BASELINE VERSIONS
    # --------------------------------------------------

    existing_versions = (
        get_existing_baseline_versions(
            card_type,
            uid
        )
    )


    # --------------------------------------------------
    # STEP 2: FIND ONLY VERSIONS OLDER THAN ACTIVE
    # --------------------------------------------------

    older_versions = [
        version
        for version in existing_versions
        if version < active_baseline_version
    ]


    # --------------------------------------------------
    # NO OLDER BASELINE EXISTS
    # --------------------------------------------------

    if not older_versions:

        return {
            "rollback_status":
                "NOT_APPLICABLE",

            "rollback_detected":
                False,

            "matched_older_version":
                None,

            "latest_authorized_version":
                active_baseline_version,

            "active_baseline_version":
                active_baseline_version,

            "checked_older_versions":
                [],

            "reason":
                (
                    "No baseline version older than "
                    "the currently active trusted "
                    "baseline exists for rollback "
                    "comparison."
                ),
        }


    # --------------------------------------------------
    # STEP 3: CHECK NEWEST OLDER VERSION FIRST
    # --------------------------------------------------

    checked_versions = []

    for older_version in sorted(
        older_versions,
        reverse=True
    ):

        checked_versions.append(
            older_version
        )


        # --------------------------------------------------
        # LOAD HMAC-VERIFIED OLDER BASELINE
        # --------------------------------------------------

        older_baseline, _ = (
            load_baseline(
                card_type,
                uid,
                version=older_version
            )
        )


        # --------------------------------------------------
        # COMPARE CURRENT STATE WITH OLDER BASELINE
        # --------------------------------------------------

        raw_memory_result = (
            verify_raw_memory(
                canonical_scan,
                older_baseline
            )
        )

        ndef_result = (
            verify_ndef_application(
                canonical_scan,
                older_baseline
            )
        )

        security_result = (
            verify_security_state(
                canonical_scan,
                older_baseline
            )
        )


        # --------------------------------------------------
        # EXACT THREE-LAYER MATCH = ROLLBACK
        # --------------------------------------------------

        if all_required_layers_match(
            raw_memory_result,
            ndef_result,
            security_result,
        ):

            return {
                "rollback_status":
                    "ROLLBACK",

                "rollback_detected":
                    True,

                "matched_older_version":
                    older_version,

                "latest_authorized_version":
                    active_baseline_version,

                "active_baseline_version":
                    active_baseline_version,

                "checked_older_versions":
                    checked_versions,

                "reason":
                    (
                        "The current NFC state exactly "
                        "matches a baseline version older "
                        "than the currently active trusted "
                        "baseline."
                    ),
            }


    # --------------------------------------------------
    # NO OLDER BASELINE MATCHED
    # --------------------------------------------------

    return {
        "rollback_status":
            "NO_OLDER_BASELINE_MATCH",

        "rollback_detected":
            False,

        "matched_older_version":
            None,

        "latest_authorized_version":
            active_baseline_version,

        "active_baseline_version":
            active_baseline_version,

        "checked_older_versions":
            checked_versions,

        "reason":
            (
                "The current NFC state does not exactly "
                "match any baseline version older than "
                "the currently active trusted baseline."
            ),
    }


# --------------------------------------------------
# SIMPLE MANUAL TEST
# --------------------------------------------------

if __name__ == "__main__":

    print(
        "rollback_detector.py loaded successfully."
    )
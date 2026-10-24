import sqlite3
from pathlib import Path

from baseline_version_manager import (
    get_active_baseline_version,
)


# --------------------------------------------------
# N3 PROJECT PATH
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATABASE_PATH = (
    PROJECT_ROOT
    / "database"
    / "n3_integrity.db"
)


# --------------------------------------------------
# NORMALIZE UID
# --------------------------------------------------

def normalize_uid(uid):
    """
    Convert UID into one consistent uppercase
    space-separated format.
    """

    if uid is None:
        return None

    return " ".join(
        uid.strip().upper().split()
    )


# --------------------------------------------------
# GET AUTHORIZED BASELINE HISTORY
# --------------------------------------------------

def get_authorized_history(
    card_type,
    uid
):
    """
    Read authorized baseline lifecycle records
    for one NFC tag from integrity_journal.
    """

    normalized_uid = normalize_uid(
        uid
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    try:

        rows = connection.execute(
            """
            SELECT
                event_type,
                previous_version,
                new_version,
                authorization_status,
                event_time_utc,
                previous_baseline_path,
                new_baseline_path
            FROM integrity_journal
            WHERE card_type = ?
              AND uid = ?
              AND authorization_status = 'AUTHORIZED'
            ORDER BY id ASC
            """,
            (
                card_type,
                normalized_uid,
            )
        ).fetchall()

    finally:

        connection.close()

    history = []

    for row in rows:

        history.append(
            {
                "event_type": row[0],
                "previous_version": row[1],
                "new_version": row[2],
                "authorization_status": row[3],
                "event_time_utc": row[4],
                "previous_baseline_path": row[5],
                "new_baseline_path": row[6],
            }
        )

    return history


# --------------------------------------------------
# GET LATEST AUTHORIZED VERSION
# --------------------------------------------------

def get_latest_authorized_version(
    card_type,
    uid
):
    """
    Return the latest authorized baseline version
    recorded in the integrity journal.
    """

    history = get_authorized_history(
        card_type,
        uid
    )

    if not history:
        return None

    versions = []

    for event in history:

        version = event.get(
            "new_version"
        )

        if isinstance(
            version,
            int
        ):
            versions.append(
                version
            )

    if not versions:
        return None

    return max(
        versions
    )


# --------------------------------------------------
# EVALUATE JOURNAL STATE
# --------------------------------------------------

def evaluate_journal_state(
    card_type,
    uid,
    baseline_version,
    verification_verdict
):
    """
    Evaluate whether the baseline used during
    verification is consistent with the currently
    ACTIVE trusted baseline and authorized history.

    Important distinction:

    latest_authorized_version
        = highest version recorded in history

    active_trusted_version
        = version currently selected for VERIFY
    """

    authorized_history = (
        get_authorized_history(
            card_type,
            uid
        )
    )

    active_trusted_version = (
        get_active_baseline_version(
            card_type,
            uid
        )
    )

    latest_authorized_version = (
        get_latest_authorized_version(
            card_type,
            uid
        )
    )


    # --------------------------------------------------
    # NO AUTHORIZED JOURNAL HISTORY
    # --------------------------------------------------

    if not authorized_history:

        return {
            "journal_status":
                "MISSING_JOURNAL_HISTORY",

            "reason":
                (
                    "No authorized integrity-journal "
                    "history exists for this NFC tag."
                ),

            "latest_authorized_version":
                None,

            "active_trusted_version":
                active_trusted_version,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # BASELINE USED MUST MATCH ACTIVE TRUSTED VERSION
    # --------------------------------------------------

    if (
        baseline_version
        != active_trusted_version
    ):

        return {
            "journal_status":
                "INCONSISTENT",

            "reason":
                (
                    "The baseline used for verification "
                    "does not match the currently active "
                    "trusted baseline version."
                ),

            "latest_authorized_version":
                latest_authorized_version,

            "active_trusted_version":
                active_trusted_version,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # CURRENT STATE MATCHES ACTIVE TRUSTED BASELINE
    # --------------------------------------------------

    if verification_verdict == "VALID":

        return {
            "journal_status":
                "AUTHORIZED_MATCH",

            "reason":
                (
                    "The current NFC state matches the "
                    "currently active trusted baseline."
                ),

            "latest_authorized_version":
                latest_authorized_version,

            "active_trusted_version":
                active_trusted_version,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # CURRENT STATE DIFFERS FROM ACTIVE TRUSTED BASELINE
    # --------------------------------------------------

    if verification_verdict == "MODIFIED":

        return {
            "journal_status":
                "UNJOURNALED_CHANGE",

            "reason":
                (
                    "The current NFC state differs from "
                    "the currently active trusted baseline "
                    "and no approved active transition "
                    "explains the detected change."
                ),

            "latest_authorized_version":
                latest_authorized_version,

            "active_trusted_version":
                active_trusted_version,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # INSUFFICIENT EVIDENCE
    # --------------------------------------------------

    return {
        "journal_status":
            "INSUFFICIENT_EVIDENCE",

        "reason":
            (
                "The active trusted baseline is available, "
                "but the current scan does not contain "
                "enough evidence for a definitive "
                "journal-state conclusion."
            ),

        "latest_authorized_version":
            latest_authorized_version,

        "active_trusted_version":
            active_trusted_version,

        "baseline_version_used":
            baseline_version,
    }

    """
    Evaluate whether the baseline used during
    verification is consistent with the authorized
    integrity-journal history.
    """

    authorized_history = (
        get_authorized_history(
            card_type,
            uid
        )
    )

    if not authorized_history:

        return {
            "journal_status":
                "MISSING_JOURNAL_HISTORY",

            "reason":
                (
                    "No authorized integrity-journal "
                    "history exists for this NFC tag."
                ),

            "latest_authorized_version":
                None,

            "baseline_version_used":
                baseline_version,
        }


    latest_authorized_version = (
        get_latest_authorized_version(
            card_type,
            uid
        )
    )


    # --------------------------------------------------
    # BASELINE VERSION IS LATEST AUTHORIZED VERSION
    # --------------------------------------------------

    if (
        baseline_version
        == latest_authorized_version
    ):

        if verification_verdict == "VALID":

            journal_status = (
                "AUTHORIZED_MATCH"
            )

            reason = (
                "The current NFC state matches the "
                "latest authorized trusted baseline."
            )

        elif verification_verdict == "MODIFIED":

            journal_status = (
                "UNJOURNALED_CHANGE"
            )

            reason = (
                "The current NFC state differs from "
                "the latest authorized baseline and "
                "no authorized transition explains "
                "the detected change."
            )

        else:

            journal_status = (
                "INSUFFICIENT_EVIDENCE"
            )

            reason = (
                "The latest authorized baseline is "
                "available, but the current scan does "
                "not contain enough evidence for a "
                "definitive journal-state conclusion."
            )

        return {
            "journal_status":
                journal_status,

            "reason":
                reason,

            "latest_authorized_version":
                latest_authorized_version,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # OLDER AUTHORIZED BASELINE VERSION USED
    # --------------------------------------------------

    if (
        baseline_version
        < latest_authorized_version
    ):

        return {
            "journal_status":
                "ROLLBACK",

            "reason":
                (
                    "Verification used an older "
                    "authorized baseline version "
                    "instead of the latest "
                    "authorized version."
                ),

            "latest_authorized_version":
                latest_authorized_version,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # BASELINE VERSION NEWER THAN JOURNAL HISTORY
    # --------------------------------------------------

    return {
        "journal_status":
            "INCONSISTENT",

        "reason":
            (
                "The baseline version used is newer "
                "than the latest authorized version "
                "recorded in the integrity journal."
            ),

        "latest_authorized_version":
            latest_authorized_version,

        "baseline_version_used":
            baseline_version,
    }


# --------------------------------------------------
# SIMPLE MANUAL TEST
# --------------------------------------------------

if __name__ == "__main__":

    print(
        "journal_state.py loaded successfully."
    )
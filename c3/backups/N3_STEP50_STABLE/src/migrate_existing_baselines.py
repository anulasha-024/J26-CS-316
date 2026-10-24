from pathlib import Path
import json
import sqlite3

from baseline_manager import load_baseline
from journal_manager import save_integrity_event


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BASELINES_DIR = PROJECT_ROOT / "baselines"
DATABASE_PATH = PROJECT_ROOT / "database" / "n3_integrity.db"


# --------------------------------------------------
# CHECK WHETHER BASELINE IS ALREADY JOURNALED
# --------------------------------------------------

def baseline_already_journaled(
    card_type,
    uid,
    version
):
    """
    Check whether this trusted baseline version
    is already represented in the integrity journal.
    """

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    try:

        row = connection.execute(
            """
            SELECT COUNT(*)
            FROM integrity_journal
            WHERE card_type = ?
              AND uid = ?
              AND new_version = ?
              AND event_type IN (
                    'ENROLLMENT',
                    'BASELINE_IMPORT'
              )
            """,
            (
                card_type,
                uid,
                version,
            )
        ).fetchone()

        return row[0] > 0

    finally:

        connection.close()


# --------------------------------------------------
# MIGRATE ONE EXISTING BASELINE
# --------------------------------------------------

def migrate_baseline(
    baseline_file
):
    """
    Verify an existing trusted baseline using HMAC
    and register it in the integrity journal as
    a historical baseline import.
    """

    print(
        "\n======================================"
    )

    print(
        "CHECKING BASELINE"
    )

    print(
        "======================================"
    )

    print(
        "File :",
        baseline_file.name
    )


    # --------------------------------------------------
    # STEP 1: READ MINIMUM METADATA
    # --------------------------------------------------

    with baseline_file.open(
        "r",
        encoding="utf-8"
    ) as file:

        metadata = json.load(
            file
        )

    card_info = metadata.get(
        "card_info",
        {}
    )

    card_type = card_info.get(
        "card_type"
    )

    uid = card_info.get(
        "uid"
    )

    version = metadata.get(
        "baseline_version"
    )

    original_enrollment_time = (
        metadata.get(
            "enrollment_time_utc"
        )
        or
        metadata.get(
            "enrollment_time"
        )
    )


    # --------------------------------------------------
    # STEP 2: VALIDATE REQUIRED METADATA
    # --------------------------------------------------

    if not card_type:

        raise ValueError(
            f"Card type missing in "
            f"{baseline_file.name}"
        )

    if not uid:

        raise ValueError(
            f"UID missing in "
            f"{baseline_file.name}"
        )

    if not isinstance(
        version,
        int
    ):

        raise ValueError(
            f"Invalid baseline version in "
            f"{baseline_file.name}"
        )


    # --------------------------------------------------
    # STEP 3: VERIFY BASELINE HMAC
    # --------------------------------------------------

    verified_baseline, verified_path = (
        load_baseline(
            card_type,
            uid,
            version=version
        )
    )

    print(
        "Card Type        :",
        card_type
    )

    print(
        "UID              :",
        uid
    )

    print(
        "Baseline Version :",
        version
    )

    print(
        "Baseline HMAC    : VALID"
    )

    print(
        "Enrollment Time  :",
        original_enrollment_time
    )


    # --------------------------------------------------
    # STEP 4: AVOID DUPLICATE MIGRATION
    # --------------------------------------------------

    if baseline_already_journaled(
        card_type,
        uid,
        version
    ):

        print(
            "Journal Status   : "
            "ALREADY RECORDED"
        )

        return


    # --------------------------------------------------
    # STEP 5: CREATE BASELINE IMPORT EVENT
    # --------------------------------------------------

    integrity_event = save_integrity_event(
        event_type="BASELINE_IMPORT",

        card_type=card_type,

        uid=uid,

        previous_version=None,

        new_version=version,

        previous_baseline_path=None,

        new_baseline_path=verified_path,

        authorization_status="AUTHORIZED",

        details={
            "migration_reason":
                (
                    "Trusted baseline existed "
                    "before integrity journal "
                    "logging was introduced."
                ),

            "original_enrollment_time_utc":
                original_enrollment_time,

            "source_baseline_file":
                baseline_file.name,

            "historical_event":
                True,
        },
    )


    # --------------------------------------------------
    # STEP 6: SHOW RESULT
    # --------------------------------------------------

    print(
        "Event Type       : BASELINE_IMPORT"
    )

    print(
        "Integrity Event  :",
        integrity_event[
            "event_id"
        ]
    )

    print(
        "Journal Status   : RECORDED"
    )


# --------------------------------------------------
# MAIN MIGRATION
# --------------------------------------------------

def main():

    print(
        "======================================"
    )

    print(
        "N3 EXISTING BASELINE MIGRATION"
    )

    print(
        "======================================"
    )

    baseline_files = sorted(
        BASELINES_DIR.glob(
            "*_V*.json"
        )
    )

    if not baseline_files:

        print(
            "No baseline files found."
        )

        return

    print(
        "Baseline Files Found :",
        len(
            baseline_files
        )
    )

    for baseline_file in baseline_files:

        migrate_baseline(
            baseline_file
        )

    print(
        "\n======================================"
    )

    print(
        "MIGRATION CHECK COMPLETE"
    )

    print(
        "======================================"
    )


# --------------------------------------------------
# START SCRIPT
# --------------------------------------------------

if __name__ == "__main__":
    main()
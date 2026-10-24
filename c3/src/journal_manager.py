from pathlib import Path
from datetime import datetime, timezone

import sqlite3
import json
import uuid


# --------------------------------------------------
# N3 DATABASE PATH
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATABASE_DIR = PROJECT_ROOT / "database"

DATABASE_PATH = DATABASE_DIR / "n3_integrity.db"


# --------------------------------------------------
# CONNECT TO DATABASE
# --------------------------------------------------

def connect_database():
    """
    Open a connection to the N3 SQLite database.
    """

    DATABASE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    return connection


# --------------------------------------------------
# SAFE VERIFICATION JOURNAL SCHEMA MIGRATION
# --------------------------------------------------

def migrate_verification_journal_schema(cursor):
    """
    Safely add new verification-summary columns
    to an existing verification_journal table.

    Existing rows are preserved.
    Missing columns are added only once.
    """

    cursor.execute(
        "PRAGMA table_info(verification_journal)"
    )

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    required_columns = {
        # Journal state
        "journal_status":
            "TEXT",

        # Time evidence
        "time_evidence_status":
            "TEXT",

        "last_known_valid_utc":
            "TEXT",

        "first_detected_modified_utc":
            "TEXT",

        "possible_window_start_utc":
            "TEXT",

        "possible_window_end_utc":
            "TEXT",

        # Performance
        "verification_latency_ms":
            "REAL",

        # Reader / acquisition metadata
        "reader_name":
            "TEXT",

        "acquisition_method":
            "TEXT",

        "interface_type":
            "TEXT",

        "source_file":
            "TEXT",

        # Rollback evidence
        "rollback_status":
            "TEXT",

        "rollback_detected":
            "INTEGER",

        "rollback_matched_version":
            "INTEGER",

        "rollback_latest_authorized_version":
            "INTEGER",

        "rollback_checked_older_versions":
            "TEXT",

        "rollback_reason":
            "TEXT",
    }

    for (
        column_name,
        column_type
    ) in required_columns.items():

        if column_name not in existing_columns:

            cursor.execute(
                f"""
                ALTER TABLE verification_journal
                ADD COLUMN {column_name} {column_type}
                """
            )


# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

def initialize_database():
    """
    Create the N3 database tables
    if they do not already exist.

    Existing verification_journal tables are
    safely migrated when new columns are required.
    """

    connection = connect_database()

    try:

        cursor = connection.cursor()


        # --------------------------------------------------
        # TABLE 1:
        # VERIFICATION HISTORY
        # --------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_journal (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_id TEXT UNIQUE NOT NULL,

                verification_time_utc TEXT NOT NULL,

                card_type TEXT,

                uid TEXT,

                baseline_version INTEGER,

                verdict TEXT NOT NULL,

                changed_layers TEXT,

                tamper_classification TEXT,

                report_path TEXT,

                reader_name TEXT,

                acquisition_method TEXT,

                interface_type TEXT,

                source_file TEXT,

                journal_status TEXT,

                time_evidence_status TEXT,

                last_known_valid_utc TEXT,

                first_detected_modified_utc TEXT,

                possible_window_start_utc TEXT,

                possible_window_end_utc TEXT,

                verification_latency_ms REAL,

                rollback_status TEXT,

                rollback_detected INTEGER,

                rollback_matched_version INTEGER,

                rollback_latest_authorized_version INTEGER,

                rollback_checked_older_versions TEXT,

                rollback_reason TEXT
            )
            """
        )


        # --------------------------------------------------
        # SAFE MIGRATION FOR EXISTING DATABASE
        # --------------------------------------------------

        migrate_verification_journal_schema(
            cursor
        )


        # --------------------------------------------------
        # TABLE 2:
        # TRUSTED BASELINE / INTEGRITY HISTORY
        # --------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS integrity_journal (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                event_id TEXT UNIQUE NOT NULL,

                event_time_utc TEXT NOT NULL,

                event_type TEXT NOT NULL,

                card_type TEXT NOT NULL,

                uid TEXT NOT NULL,

                previous_version INTEGER,

                new_version INTEGER NOT NULL,

                previous_baseline_path TEXT,

                new_baseline_path TEXT NOT NULL,

                authorization_status TEXT NOT NULL,

                details TEXT
            )
            """
        )

        connection.commit()

    finally:

        connection.close()


# --------------------------------------------------
# SAVE VERIFICATION EVENT TO JOURNAL
# --------------------------------------------------

def save_verification_to_journal(
    report,
    report_path
):
    """
    Save one N3 verification report summary
    into the SQLite verification journal.

    This includes:

    - verification verdict
    - changed layers
    - change classification
    - reader / acquisition metadata
    - journal state
    - time-evidence summary
    - verification latency
    - rollback evidence
    """

    initialize_database()

    connection = connect_database()

    try:

        cursor = connection.cursor()


        # --------------------------------------------------
        # BASIC REPORT INFORMATION
        # --------------------------------------------------

        scan_id = report.get(
            "scan_id"
        )

        verification_time_utc = report.get(
            "verification_time_utc"
        )


        # --------------------------------------------------
        # CARD INFORMATION
        # --------------------------------------------------

        card = report.get(
            "card",
            {}
        )

        card_type = card.get(
            "card_type"
        )

        uid = card.get(
            "uid"
        )


        # --------------------------------------------------
        # BASELINE INFORMATION
        # --------------------------------------------------

        baseline = report.get(
            "baseline",
            {}
        )

        baseline_version = baseline.get(
            "baseline_version"
        )


        # --------------------------------------------------
        # FINAL DECISION
        # --------------------------------------------------

        final_decision = report.get(
            "final_decision",
            {}
        )

        verdict = final_decision.get(
            "verdict"
        )

        changed_layers = final_decision.get(
            "changed_layers",
            []
        )


        # --------------------------------------------------
        # CHANGE / TAMPER CLASSIFICATION
        # --------------------------------------------------

        tamper_classification = report.get(
            "tamper_classification",
            []
        )


        # --------------------------------------------------
        # READER / ACQUISITION METADATA
        # --------------------------------------------------

        reader_metadata = report.get(
            "reader_metadata",
            {}
        )

        reader_name = reader_metadata.get(
            "reader_name"
        )

        acquisition_method = reader_metadata.get(
            "acquisition_method"
        )

        interface_type = reader_metadata.get(
            "interface_type"
        )

        source_file = reader_metadata.get(
            "source_file"
        )


        # --------------------------------------------------
        # JOURNAL STATE
        # --------------------------------------------------

        journal_state = report.get(
            "journal_state",
            {}
        )

        journal_status = journal_state.get(
            "journal_status"
        )


        # --------------------------------------------------
        # TIME EVIDENCE
        # --------------------------------------------------

        time_evidence = report.get(
            "time_evidence",
            {}
        )

        time_evidence_status = (
            time_evidence.get(
                "status"
            )
        )

        last_known_valid_utc = (
            time_evidence.get(
                "last_known_valid_utc"
            )
        )

        first_detected_modified_utc = (
            time_evidence.get(
                "first_detected_modified_utc"
            )
        )

        possible_window = (
            time_evidence.get(
                "possible_modification_window",
                {}
            )
        )

        possible_window_start_utc = (
            possible_window.get(
                "start_utc"
            )
        )

        possible_window_end_utc = (
            possible_window.get(
                "end_utc"
            )
        )


        # --------------------------------------------------
        # PERFORMANCE METRICS
        # --------------------------------------------------

        performance_metrics = report.get(
            "performance_metrics",
            {}
        )

        verification_latency_ms = (
            performance_metrics.get(
                "verification_latency_ms"
            )
        )


        # --------------------------------------------------
        # ROLLBACK EVIDENCE
        # --------------------------------------------------

        rollback_evidence = report.get(
            "rollback_evidence"
        )

        rollback_status = None

        rollback_detected = None

        rollback_matched_version = None

        rollback_latest_authorized_version = None

        rollback_checked_older_versions_json = None

        rollback_reason = None


        if isinstance(
            rollback_evidence,
            dict
        ):

            rollback_status = (
                rollback_evidence.get(
                    "rollback_status"
                )
            )

            rollback_detected_value = (
                rollback_evidence.get(
                    "rollback_detected"
                )
            )

            if rollback_detected_value is not None:

                rollback_detected = int(
                    bool(
                        rollback_detected_value
                    )
                )

            rollback_matched_version = (
                rollback_evidence.get(
                    "matched_older_version"
                )
            )

            rollback_latest_authorized_version = (
                rollback_evidence.get(
                    "latest_authorized_version"
                )
            )

            rollback_checked_older_versions = (
                rollback_evidence.get(
                    "checked_older_versions"
                )
            )

            if isinstance(
                rollback_checked_older_versions,
                list
            ):

                rollback_checked_older_versions_json = (
                    json.dumps(
                        rollback_checked_older_versions
                    )
                )

            rollback_reason = (
                rollback_evidence.get(
                    "reason"
                )
            )


        # --------------------------------------------------
        # CONVERT LISTS TO JSON TEXT
        # --------------------------------------------------

        changed_layers_json = json.dumps(
            changed_layers
        )

        tamper_classification_json = json.dumps(
            tamper_classification
        )


        # --------------------------------------------------
        # INSERT VERIFICATION JOURNAL RECORD
        # --------------------------------------------------

        cursor.execute(
            """
            INSERT INTO verification_journal (

                scan_id,

                verification_time_utc,

                card_type,

                uid,

                baseline_version,

                verdict,

                changed_layers,

                tamper_classification,

                report_path,

                reader_name,

                acquisition_method,

                interface_type,

                source_file,

                journal_status,

                time_evidence_status,

                last_known_valid_utc,

                first_detected_modified_utc,

                possible_window_start_utc,

                possible_window_end_utc,

                verification_latency_ms,

                rollback_status,

                rollback_detected,

                rollback_matched_version,

                rollback_latest_authorized_version,

                rollback_checked_older_versions,

                rollback_reason

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?
            )
            """,

            (
                scan_id,

                verification_time_utc,

                card_type,

                uid,

                baseline_version,

                verdict,

                changed_layers_json,

                tamper_classification_json,

                str(
                    report_path
                ),

                reader_name,

                acquisition_method,

                interface_type,

                source_file,

                journal_status,

                time_evidence_status,

                last_known_valid_utc,

                first_detected_modified_utc,

                possible_window_start_utc,

                possible_window_end_utc,

                verification_latency_ms,

                rollback_status,

                rollback_detected,

                rollback_matched_version,

                rollback_latest_authorized_version,

                rollback_checked_older_versions_json,

                rollback_reason,
            )
        )

        connection.commit()

    finally:

        connection.close()


# --------------------------------------------------
# SAVE TRUSTED INTEGRITY EVENT
# --------------------------------------------------

def save_integrity_event(
    event_type,
    card_type,
    uid,
    new_version,
    new_baseline_path,
    previous_version=None,
    previous_baseline_path=None,
    authorization_status="AUTHORIZED",
    details=None,
):
    """
    Save a trusted baseline lifecycle event.

    Examples:

    - ENROLLMENT:
      first trusted baseline V1

    - AUTHORIZED_UPDATE:
      V1 -> V2
    """

    initialize_database()

    if not event_type:

        raise ValueError(
            "Integrity event type is required."
        )

    if not card_type:

        raise ValueError(
            "Card type is required."
        )

    if not uid:

        raise ValueError(
            "UID is required."
        )

    if (
        not isinstance(
            new_version,
            int
        )
        or new_version < 1
    ):

        raise ValueError(
            "New baseline version must be "
            "a positive integer."
        )

    if not new_baseline_path:

        raise ValueError(
            "New baseline path is required."
        )


    # --------------------------------------------------
    # CREATE EVENT ID AND TIME
    # --------------------------------------------------

    event_id = str(
        uuid.uuid4()
    )

    event_time_utc = datetime.now(
        timezone.utc
    ).isoformat()


    # --------------------------------------------------
    # CONVERT DETAILS TO JSON TEXT
    # --------------------------------------------------

    if details is None:

        details = {}

    details_json = json.dumps(
        details
    )


    # --------------------------------------------------
    # SAVE EVENT TO SQLITE
    # --------------------------------------------------

    connection = connect_database()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO integrity_journal (

                event_id,

                event_time_utc,

                event_type,

                card_type,

                uid,

                previous_version,

                new_version,

                previous_baseline_path,

                new_baseline_path,

                authorization_status,

                details

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,

            (
                event_id,

                event_time_utc,

                event_type,

                card_type,

                uid,

                previous_version,

                new_version,

                (
                    str(
                        previous_baseline_path
                    )
                    if previous_baseline_path
                    else None
                ),

                str(
                    new_baseline_path
                ),

                authorization_status,

                details_json,
            )
        )

        connection.commit()

    finally:

        connection.close()


    # --------------------------------------------------
    # RETURN SAVED EVENT INFORMATION
    # --------------------------------------------------

    return {
        "event_id":
            event_id,

        "event_time_utc":
            event_time_utc,

        "event_type":
            event_type,

        "card_type":
            card_type,

        "uid":
            uid,

        "previous_version":
            previous_version,

        "new_version":
            new_version,

        "authorization_status":
            authorization_status,
    }


# --------------------------------------------------
# RUN DATABASE INITIALIZATION
# --------------------------------------------------

if __name__ == "__main__":

    initialize_database()

    print(
        "N3 SQLite database initialized successfully."
    )

    print(
        "Database Path :",
        DATABASE_PATH
    )
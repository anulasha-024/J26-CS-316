from pathlib import Path

import time
import shutil
import argparse


from parser import parse_flipper_nfc

from canonicalizer import canonicalize_scan

from scan_quality import assess_scan_quality

from mode_manager import normalize_mode


from baseline_manager import (
    build_baseline,
    save_baseline,
    load_baseline,
)


from baseline_version_manager import (
    get_latest_baseline_version,
)


from authorized_update_manager import (
    create_authorized_baseline_update,
)


from verifier import (
    verify_raw_memory,
    verify_ndef_application,
    verify_security_state,
)


from ndef_parser import extract_ndef_evidence


from security_state import (
    extract_ntag215_security_state,
)


from decision_engine import (
    make_final_decision,
    make_unknown_decision,
)


from region_mapper import (
    add_ntag215_regions,
)


from tamper_classifier import (
    classify_change,
)


from report_generator import (
    generate_verification_report,
    generate_unknown_report,
    save_verification_report,
)


from journal_manager import (
    save_verification_to_journal,
    save_integrity_event,
)


from journal_state import (
    evaluate_journal_state,
)


from time_evidence import (
    build_time_evidence,
)


from performance_metrics import (
    start_timer,
    calculate_elapsed_ms,
)


from reader_metadata import (
    build_reader_metadata,
)


from rollback_detector import (
    detect_rollback,
)


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

INCOMING_DIR = PROJECT_ROOT / "data" / "incoming"

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

FAILED_DIR = PROJECT_ROOT / "data" / "failed"

CHECK_INTERVAL = 1


# --------------------------------------------------
# CHECK WHETHER FILE IS READY
# --------------------------------------------------

def wait_until_file_ready(file_path, timeout=15):
    """
    Wait until the NFC file has completely finished
    writing before parsing it.
    """

    start_time = time.time()

    previous_size = -1
    stable_count = 0

    while time.time() - start_time < timeout:

        try:

            current_size = file_path.stat().st_size

            with file_path.open("rb") as file:
                file.read(1)

            if (
                current_size == previous_size
                and current_size > 0
            ):

                stable_count += 1

                if stable_count >= 2:
                    return True

            else:

                stable_count = 0
                previous_size = current_size

        except (PermissionError, OSError):

            stable_count = 0

        time.sleep(1)

    return False


# --------------------------------------------------
# PROCESS NEW NFC SCAN
# --------------------------------------------------

def process_scan(file_path):
    """
    Parse, canonicalize, attach reader metadata,
    extract NDEF evidence,
    extract security-state evidence,
    and assess scan quality.
    """

    print("\n======================================")
    print("NEW NFC SCAN DETECTED")
    print("======================================")

    print(
        "File :",
        file_path.name
    )


    # --------------------------------------------------
    # STEP 1: PARSE NFC FILE
    # --------------------------------------------------

    card_info, pages = parse_flipper_nfc(
        file_path
    )

    print(
        "\n--- NFC INFORMATION ---"
    )

    print(
        "Device Type :",
        card_info.get(
            "Device type"
        )
    )

    print(
        "Card Type   :",
        card_info.get(
            "NTAG/Ultralight type"
        )
    )

    print(
        "UID         :",
        card_info.get(
            "UID"
        )
    )

    print(
        "Pages Total :",
        card_info.get(
            "Pages total"
        )
    )

    print(
        "Pages Read  :",
        card_info.get(
            "Pages read"
        )
    )

    print(
        "Parsed Pages:",
        len(pages)
    )

    print(
        "\nParser Result: SUCCESS"
    )


    # --------------------------------------------------
    # STEP 2: CANONICALIZE NFC SCAN
    # --------------------------------------------------

    canonical_scan = canonicalize_scan(
        card_info,
        pages
    )

    print(
        "\n--- CANONICALIZATION ---"
    )

    print(
        "Canonical UID   :",
        canonical_scan[
            "card_info"
        ]["uid"]
    )

    print(
        "Canonical Pages :",
        len(
            canonical_scan[
                "memory_pages"
            ]
        )
    )

    print(
        "\nCanonicalizer Result: SUCCESS"
    )


    # --------------------------------------------------
    # STEP 3: READER / ACQUISITION METADATA
    # --------------------------------------------------

    reader_metadata = build_reader_metadata(
        source_file=file_path.name,
        reader_name="Flipper Zero",
        acquisition_method="NFC_DUMP_FILE",
        interface_type="FILE_IMPORT",
    )

    canonical_scan[
        "reader_metadata"
    ] = reader_metadata

    print(
        "\n--- READER / ACQUISITION METADATA ---"
    )

    print(
        "Reader Name        :",
        reader_metadata.get(
            "reader_name"
        )
    )

    print(
        "Acquisition Method :",
        reader_metadata.get(
            "acquisition_method"
        )
    )

    print(
        "Interface Type     :",
        reader_metadata.get(
            "interface_type"
        )
    )

    print(
        "Source File        :",
        reader_metadata.get(
            "source_file"
        )
    )


    # --------------------------------------------------
    # STEP 4: APPLICATION / NDEF EVIDENCE
    # --------------------------------------------------

    ndef_evidence = extract_ndef_evidence(
        canonical_scan
    )

    canonical_scan[
        "ndef_evidence"
    ] = ndef_evidence

    print(
        "\n--- APPLICATION / NDEF EVIDENCE ---"
    )

    print(
        "NDEF Present :",
        ndef_evidence[
            "ndef_present"
        ]
    )

    if ndef_evidence[
        "record"
    ]:

        print(
            "Record Type  :",
            ndef_evidence[
                "record"
            ].get(
                "record_type"
            )
        )

        print(
            "Language     :",
            ndef_evidence[
                "record"
            ].get(
                "language"
            )
        )

        print(
            "Encoding     :",
            ndef_evidence[
                "record"
            ].get(
                "encoding"
            )
        )

        print(
            "Text         :",
            ndef_evidence[
                "record"
            ].get(
                "text"
            )
        )

    else:

        print(
            "No supported NDEF Text Record found."
        )


    # --------------------------------------------------
    # STEP 5: SECURITY-STATE EVIDENCE
    # --------------------------------------------------

    security_state = (
        extract_ntag215_security_state(
            canonical_scan
        )
    )

    canonical_scan[
        "security_state"
    ] = security_state

    print(
        "\n--- SECURITY-STATE EVIDENCE ---"
    )

    print(
        "Supported         :",
        security_state.get(
            "supported"
        )
    )

    print(
        "Evidence Complete :",
        security_state.get(
            "evidence_complete"
        )
    )

    if security_state.get(
        "evidence_complete"
    ):

        print(
            "Static Lock Bytes  :",
            security_state.get(
                "static_lock_bytes"
            )
        )

        print(
            "Dynamic Lock Bytes :",
            security_state.get(
                "dynamic_lock_bytes"
            )
        )

        configuration = security_state.get(
            "configuration",
            {}
        )

        print(
            "AUTH0 Page         :",
            configuration.get(
                "auth0_page"
            )
        )

        print(
            "AUTH0 Hex          :",
            configuration.get(
                "auth0_hex"
            )
        )

        print(
            "Protection Enabled :",
            configuration.get(
                "password_protection_enabled"
            )
        )

        print(
            "Protection Mode    :",
            configuration.get(
                "protection_mode"
            )
        )

        print(
            "Configuration Lock :",
            configuration.get(
                "configuration_locked"
            )
        )

        print(
            "Authentication Lim :",
            configuration.get(
                "auth_limit"
            )
        )

        print(
            "NFC Counter Enabled:",
            configuration.get(
                "nfc_counter_enabled"
            )
        )

        print(
            "Counter PWD Protect:",
            configuration.get(
                "nfc_counter_password_protected"
            )
        )

    else:

        print(
            "Security-state evidence is incomplete."
        )

        if security_state.get(
            "missing_pages"
        ):

            print(
                "Missing Pages      :",
                security_state.get(
                    "missing_pages"
                )
            )

        if security_state.get(
            "reason"
        ):

            print(
                "Reason             :",
                security_state.get(
                    "reason"
                )
            )


    # --------------------------------------------------
    # STEP 6: SCAN QUALITY CHECK
    # --------------------------------------------------

    quality_result = assess_scan_quality(
        canonical_scan
    )

    print(
        "\n--- SCAN QUALITY ---"
    )

    print(
        "Quality Status :",
        quality_result[
            "quality_status"
        ]
    )

    print(
        "Card Type      :",
        quality_result[
            "card_type"
        ]
    )

    print(
        "UID            :",
        quality_result[
            "uid"
        ]
    )

    print(
        "Pages Total    :",
        quality_result[
            "pages_total"
        ]
    )

    print(
        "Pages Read     :",
        quality_result[
            "pages_read"
        ]
    )

    print(
        "Parsed Pages   :",
        quality_result[
            "parsed_pages"
        ]
    )

    if quality_result[
        "reasons"
    ]:

        print(
            "\nQuality Issues:"
        )

        for reason in quality_result[
            "reasons"
        ]:

            print(
                "-",
                reason
            )

    print(
        "\nScan Quality Result:",
        quality_result[
            "quality_status"
        ]
    )

    return (
        canonical_scan,
        quality_result,
    )


# --------------------------------------------------
# MOVE PROCESSED FILE
# --------------------------------------------------

def move_to_processed(file_path):
    """
    Move a completed acquisition from
    incoming to processed.
    """

    destination = (
        PROCESSED_DIR /
        file_path.name
    )

    if destination.exists():

        timestamp = time.strftime(
            "%Y%m%d_%H%M%S"
        )

        destination = PROCESSED_DIR / (
            f"{file_path.stem}_"
            f"{timestamp}"
            f"{file_path.suffix}"
        )

        counter = 1

        while destination.exists():

            destination = PROCESSED_DIR / (
                f"{file_path.stem}_"
                f"{timestamp}_"
                f"{counter}"
                f"{file_path.suffix}"
            )

            counter += 1

    shutil.move(
        str(file_path),
        str(destination)
    )

    print(
        "\nStored In :",
        destination
    )


# --------------------------------------------------
# MOVE FAILED FILE
# --------------------------------------------------

def move_to_failed(file_path):
    """
    Move an acquisition that could not be
    processed into the failed folder.
    """

    destination = (
        FAILED_DIR /
        file_path.name
    )

    if destination.exists():

        timestamp = time.strftime(
            "%Y%m%d_%H%M%S"
        )

        destination = FAILED_DIR / (
            f"{file_path.stem}_"
            f"{timestamp}"
            f"{file_path.suffix}"
        )

        counter = 1

        while destination.exists():

            destination = FAILED_DIR / (
                f"{file_path.stem}_"
                f"{timestamp}_"
                f"{counter}"
                f"{file_path.suffix}"
            )

            counter += 1

    shutil.move(
        str(file_path),
        str(destination)
    )

    print(
        "\nFailed Scan Stored In :",
        destination
    )


# --------------------------------------------------
# HANDLE ENROLL MODE
# --------------------------------------------------

def handle_enrollment(
    canonical_scan,
    file_path
):
    """
    Create and save the initial trusted baseline
    and record the enrollment in the integrity journal.
    """

    print(
        "\n--- TRUSTED BASELINE ENROLLMENT ---"
    )

    baseline = build_baseline(
        canonical_scan,
        file_path,
        version=1
    )

    baseline_path = save_baseline(
        baseline
    )

    integrity_event = save_integrity_event(
        event_type="ENROLLMENT",

        card_type=baseline[
            "card_info"
        ]["card_type"],

        uid=baseline[
            "card_info"
        ]["uid"],

        new_version=baseline[
            "baseline_version"
        ],

        new_baseline_path=baseline_path,

        previous_version=None,

        previous_baseline_path=None,

        authorization_status="AUTHORIZED",

        details={
            "source_file":
                file_path.name
        },
    )

    print(
        "Baseline Version  :",
        baseline[
            "baseline_version"
        ]
    )

    print(
        "Enrollment Result : SUCCESS"
    )

    print(
        "Baseline Stored   :",
        baseline_path
    )

    print(
        "Integrity Event ID:",
        integrity_event[
            "event_id"
        ]
    )

    print(
        "Journal Status    : RECORDED"
    )


# --------------------------------------------------
# HANDLE AUTHORIZED UPDATE MODE
# --------------------------------------------------

def handle_authorized_update(
    canonical_scan,
    file_path
):
    """
    Create the next trusted baseline version
    and record the authorized transition
    in the integrity journal.
    """

    print(
        "\n--- AUTHORIZED BASELINE UPDATE ---"
    )

    update_result = (
        create_authorized_baseline_update(
            canonical_scan,
            file_path
        )
    )

    integrity_event = save_integrity_event(
        event_type="AUTHORIZED_UPDATE",

        card_type=update_result[
            "card_type"
        ],

        uid=update_result[
            "uid"
        ],

        previous_version=update_result[
            "previous_version"
        ],

        new_version=update_result[
            "new_version"
        ],

        previous_baseline_path=update_result[
            "previous_baseline_path"
        ],

        new_baseline_path=update_result[
            "new_baseline_path"
        ],

        authorization_status="AUTHORIZED",

        details={
            "source_file":
                file_path.name
        },
    )

    print(
        "Card Type         :",
        update_result[
            "card_type"
        ]
    )

    print(
        "UID               :",
        update_result[
            "uid"
        ]
    )

    print(
        "Previous Version  :",
        update_result[
            "previous_version"
        ]
    )

    print(
        "New Version       :",
        update_result[
            "new_version"
        ]
    )

    print(
        "Previous Baseline :",
        update_result[
            "previous_baseline_path"
        ]
    )

    print(
        "New Baseline      :",
        update_result[
            "new_baseline_path"
        ]
    )

    print(
        "Integrity Event ID:",
        integrity_event[
            "event_id"
        ]
    )

    print(
        "Journal Status    : RECORDED"
    )

    print(
        "Update Result     : SUCCESS"
    )


# --------------------------------------------------
# HANDLE VERIFY MODE
# --------------------------------------------------

def handle_verification(canonical_scan):
    """
    Automatically locate the latest trusted
    baseline version, verify the current NFC scan,
    evaluate rollback evidence,
    evaluate the journal state,
    build time evidence,
    and measure verification latency.
    """

    # --------------------------------------------------
    # START VERIFICATION PERFORMANCE TIMER
    # --------------------------------------------------

    verification_timer = start_timer()

    print(
        "\n--- VERIFICATION MODE ---"
    )

    card_info = canonical_scan[
        "card_info"
    ]

    card_type = card_info.get(
        "card_type"
    )

    uid = card_info.get(
        "uid"
    )

    print(
        "Card Type :",
        card_type
    )

    print(
        "UID       :",
        uid
    )


    # --------------------------------------------------
    # STEP 1: FIND LATEST TRUSTED BASELINE VERSION
    # --------------------------------------------------

    latest_version = (
        get_latest_baseline_version(
            card_type,
            uid
        )
    )

    if latest_version is None:

        raise FileNotFoundError(
            "Trusted baseline was not found "
            "for this NFC tag."
        )

    print(
        "Latest Baseline Version :",
        latest_version
    )


    # --------------------------------------------------
    # STEP 2: LOAD LATEST TRUSTED BASELINE
    # --------------------------------------------------

    baseline, baseline_path = load_baseline(
        card_type,
        uid,
        version=latest_version
    )

    print(
        "\n--- BASELINE INTEGRITY ---"
    )

    print(
        "Baseline HMAC    : VALID"
    )

    print(
        "Baseline Version :",
        baseline[
            "baseline_version"
        ]
    )

    print(
        "Baseline Loaded  :",
        baseline_path
    )


    # --------------------------------------------------
    # STEP 3: RAW MEMORY VERIFICATION
    # --------------------------------------------------

    raw_memory_result = verify_raw_memory(
        canonical_scan,
        baseline
    )

    raw_memory_result[
        "changed_pages"
    ] = add_ntag215_regions(
        raw_memory_result[
            "changed_pages"
        ]
    )

    print(
        "\n--- RAW MEMORY VERIFICATION ---"
    )

    print(
        "Status             :",
        raw_memory_result[
            "status"
        ]
    )

    print(
        "Changed Page Count :",
        raw_memory_result[
            "changed_page_count"
        ]
    )

    if raw_memory_result[
        "changed_pages"
    ]:

        print(
            "\nChanged Pages:"
        )

        for change in raw_memory_result[
            "changed_pages"
        ]:

            print(
                f"Page {change['page']}:"
            )

            print(
                "  Region    :",
                change[
                    "region"
                ]
            )

            print(
                "  Old Value :",
                change[
                    "old_value"
                ]
            )

            print(
                "  New Value :",
                change[
                    "new_value"
                ]
            )

    else:

        print(
            "No raw memory changes detected."
        )


    # --------------------------------------------------
    # STEP 4: APPLICATION / NDEF VERIFICATION
    # --------------------------------------------------

    ndef_result = verify_ndef_application(
        canonical_scan,
        baseline
    )

    print(
        "\n--- APPLICATION / NDEF VERIFICATION ---"
    )

    print(
        "Status              :",
        ndef_result[
            "status"
        ]
    )

    print(
        "Changed Field Count :",
        ndef_result[
            "changed_field_count"
        ]
    )

    if ndef_result[
        "changed_fields"
    ]:

        print(
            "\nChanged NDEF Fields:"
        )

        for change in ndef_result[
            "changed_fields"
        ]:

            print(
                f"Field: {change['field']}"
            )

            print(
                "  Old Value :",
                change[
                    "old_value"
                ]
            )

            print(
                "  New Value :",
                change[
                    "new_value"
                ]
            )

    else:

        print(
            "No NDEF application changes detected."
        )


    # --------------------------------------------------
    # STEP 5: SECURITY-STATE VERIFICATION
    # --------------------------------------------------

    security_result = verify_security_state(
        canonical_scan,
        baseline
    )

    print(
        "\n--- SECURITY-STATE VERIFICATION ---"
    )

    print(
        "Status              :",
        security_result[
            "status"
        ]
    )

    print(
        "Changed Field Count :",
        security_result[
            "changed_field_count"
        ]
    )

    if security_result[
        "changed_fields"
    ]:

        print(
            "\nChanged Security Fields:"
        )

        for change in security_result[
            "changed_fields"
        ]:

            print(
                f"Field: {change['field']}"
            )

            print(
                "  Old Value :",
                change[
                    "old_value"
                ]
            )

            print(
                "  New Value :",
                change[
                    "new_value"
                ]
            )

    elif security_result.get(
        "reason"
    ):

        print(
            "Reason :",
            security_result[
                "reason"
            ]
        )

    else:

        print(
            "No security-state changes detected."
        )


    # --------------------------------------------------
    # STEP 6: FINAL N3 DECISION
    # --------------------------------------------------

    final_decision = make_final_decision(
        raw_memory_result,
        ndef_result,
        security_result
    )


    # --------------------------------------------------
    # STEP 7: ROLLBACK DETECTION
    # --------------------------------------------------

    if final_decision[
        "verdict"
    ] == "MODIFIED":

        rollback_result = detect_rollback(
            canonical_scan=canonical_scan,
            card_type=card_type,
            uid=uid,
            latest_baseline_version=latest_version,
        )

    elif final_decision[
        "verdict"
    ] == "VALID":

        rollback_result = {
            "rollback_status":
                "NOT_REQUIRED",

            "rollback_detected":
                False,

            "matched_older_version":
                None,

            "latest_authorized_version":
                latest_version,

            "checked_older_versions":
                [],

            "reason":
                (
                    "Rollback comparison is not required "
                    "because the current NFC state matches "
                    "the latest trusted baseline."
                ),
        }

    else:

        rollback_result = {
            "rollback_status":
                "NOT_EVALUATED",

            "rollback_detected":
                False,

            "matched_older_version":
                None,

            "latest_authorized_version":
                latest_version,

            "checked_older_versions":
                [],

            "reason":
                (
                    "Rollback comparison was not evaluated "
                    "because the verification result does "
                    "not provide sufficient confirmed "
                    "evidence."
                ),
        }

    print(
        "\n--- ROLLBACK DETECTION ---"
    )

    print(
        "Rollback Status :",
        rollback_result[
            "rollback_status"
        ]
    )

    print(
        "Rollback Detected :",
        rollback_result[
            "rollback_detected"
        ]
    )

    print(
        "Matched Older Version :",
        rollback_result[
            "matched_older_version"
        ]
    )

    print(
        "Latest Authorized Version :",
        rollback_result[
            "latest_authorized_version"
        ]
    )

    print(
        "Checked Older Versions :",
        rollback_result[
            "checked_older_versions"
        ]
    )

    print(
        "Reason :",
        rollback_result[
            "reason"
        ]
    )


    # --------------------------------------------------
    # STEP 8: JOURNAL-STATE VERIFICATION
    # --------------------------------------------------

    journal_state = evaluate_journal_state(
        card_type=card_type,

        uid=uid,

        baseline_version=baseline[
            "baseline_version"
        ],

        verification_verdict=final_decision[
            "verdict"
        ],
    )


    # --------------------------------------------------
    # APPLY TRUE ROLLBACK RESULT TO JOURNAL STATE
    # --------------------------------------------------

    if rollback_result.get(
        "rollback_detected"
    ):

        journal_state[
            "journal_status"
        ] = "ROLLBACK"

        journal_state[
            "reason"
        ] = (
            "The current NFC state does not match "
            "the latest authorized baseline, but it "
            "exactly matches an older authorized "
            "baseline version."
        )

        journal_state[
            "rollback_matched_version"
        ] = rollback_result.get(
            "matched_older_version"
        )


    print(
        "\n--- JOURNAL-STATE VERIFICATION ---"
    )

    print(
        "Journal Status :",
        journal_state[
            "journal_status"
        ]
    )

    print(
        "Reason         :",
        journal_state[
            "reason"
        ]
    )

    print(
        "Latest Authorized Version :",
        journal_state[
            "latest_authorized_version"
        ]
    )

    print(
        "Baseline Version Used     :",
        journal_state[
            "baseline_version_used"
        ]
    )

    if journal_state.get(
        "rollback_matched_version"
    ) is not None:

        print(
            "Rollback Matched Version :",
            journal_state[
                "rollback_matched_version"
            ]
        )


    # --------------------------------------------------
    # STEP 9: CHANGE CLASSIFICATION
    # --------------------------------------------------

    tamper_classes = classify_change(
        raw_memory_result,
        ndef_result,
        security_result
    )


    # --------------------------------------------------
    # STEP 10: STRUCTURED VERIFICATION REPORT
    # --------------------------------------------------

    verification_report = (
        generate_verification_report(
            canonical_scan,
            baseline,
            raw_memory_result,
            ndef_result,
            security_result,
            final_decision,
            tamper_classes,
            journal_state=journal_state,
        )
    )


    # --------------------------------------------------
    # ADD ROLLBACK EVIDENCE TO REPORT
    # --------------------------------------------------

    verification_report[
        "rollback_evidence"
    ] = rollback_result


    # --------------------------------------------------
    # STEP 11: BUILD TIME EVIDENCE
    # --------------------------------------------------

    time_evidence = build_time_evidence(
        card_type=card_type,

        uid=uid,

        current_verdict=final_decision[
            "verdict"
        ],

        current_verification_time_utc=(
            verification_report[
                "verification_time_utc"
            ]
        ),

        current_scan_id=(
            verification_report[
                "scan_id"
            ]
        ),

        trusted_baseline_time_utc=(
            baseline.get(
                "enrollment_time_utc"
            )
        ),

        trusted_baseline_version=(
            baseline.get(
                "baseline_version"
            )
        ),
    )


    # --------------------------------------------------
    # STEP 12: ADD TIME EVIDENCE TO REPORT
    # --------------------------------------------------

    verification_report[
        "time_evidence"
    ] = time_evidence

    print(
        "\n--- TIME EVIDENCE ---"
    )

    print(
        "Status :",
        time_evidence[
            "status"
        ]
    )

    print(
        "Last Known Valid :",
        time_evidence[
            "last_known_valid_utc"
        ]
    )

    print(
        "Last Known Valid Source :",
        time_evidence[
            "last_known_valid_source"
        ]
    )

    print(
        "Last Known Valid Baseline Version :",
        time_evidence[
            "last_known_valid_baseline_version"
        ]
    )

    print(
        "First Detected Modified :",
        time_evidence[
            "first_detected_modified_utc"
        ]
    )

    print(
        "Possible Window Start :",
        time_evidence[
            "possible_modification_window"
        ]["start_utc"]
    )

    print(
        "Possible Window End   :",
        time_evidence[
            "possible_modification_window"
        ]["end_utc"]
    )

    print(
        "Exact Modification Time :",
        time_evidence[
            "exact_modification_time_utc"
        ]
    )

    print(
        "Reason :",
        time_evidence[
            "reason"
        ]
    )


    # --------------------------------------------------
    # STEP 13: PERFORMANCE / VERIFICATION LATENCY
    # --------------------------------------------------

    verification_latency_ms = (
        calculate_elapsed_ms(
            verification_timer
        )
    )

    verification_report[
        "performance_metrics"
    ] = {
        "verification_latency_ms":
            verification_latency_ms,

        "measurement_scope":
            (
                "N3 verification processing from "
                "verification start until structured "
                "report preparation, excluding report "
                "and SQLite persistence."
            ),
    }

    print(
        "\n--- PERFORMANCE METRICS ---"
    )

    print(
        "Verification Latency :",
        verification_latency_ms,
        "ms"
    )


    # --------------------------------------------------
    # STEP 14: SAVE REPORT AS JSON
    # --------------------------------------------------

    report_path = save_verification_report(
        verification_report
    )


    # --------------------------------------------------
    # STEP 15: SAVE VERIFICATION TO SQLITE
    # --------------------------------------------------

    save_verification_to_journal(
        verification_report,
        report_path
    )


    # --------------------------------------------------
    # FINAL OUTPUT
    # --------------------------------------------------

    print(
        "\n======================================"
    )

    print(
        "N3 FINAL VERDICT"
    )

    print(
        "======================================"
    )

    print(
        "Verdict :",
        final_decision[
            "verdict"
        ]
    )

    print(
        "Reason  :",
        final_decision[
            "reason"
        ]
    )

    print(
        "Rollback Status :",
        rollback_result[
            "rollback_status"
        ]
    )

    print(
        "Rollback Detected :",
        rollback_result[
            "rollback_detected"
        ]
    )

    print(
        "Journal Status :",
        journal_state[
            "journal_status"
        ]
    )

    if journal_state.get(
        "rollback_matched_version"
    ) is not None:

        print(
            "Rollback Matched Version :",
            journal_state[
                "rollback_matched_version"
            ]
        )

    print(
        "Time Evidence Status :",
        time_evidence[
            "status"
        ]
    )

    print(
        "Verification Latency :",
        verification_latency_ms,
        "ms"
    )

    print(
        "\nLayer Results:"
    )

    for layer, status in final_decision[
        "layer_statuses"
    ].items():

        print(
            f"{layer} : {status}"
        )

    print(
        "\nTamper Classification:"
    )

    for tamper_class in tamper_classes:

        print(
            "-",
            tamper_class
        )

    print(
        "\n--- STRUCTURED VERIFICATION REPORT ---"
    )

    print(
        "Scan ID :",
        verification_report[
            "scan_id"
        ]
    )

    print(
        "Verification Time :",
        verification_report[
            "verification_time_utc"
        ]
    )

    print(
        "Baseline Version Used :",
        baseline[
            "baseline_version"
        ]
    )

    print(
        "Verification Latency :",
        verification_latency_ms,
        "ms"
    )

    print(
        "Report Status : GENERATED"
    )

    print(
        "Report Stored :",
        report_path
    )

    if final_decision[
        "verdict"
    ] == "MODIFIED":

        changed_layers = final_decision.get(
            "changed_layers",
            []
        )

        if changed_layers:

            print(
                "\nChanged Layers:"
            )

            for layer in changed_layers:

                print(
                    "-",
                    layer
                )

    if final_decision[
        "verdict"
    ] == "UNKNOWN":

        insufficient_layers = (
            final_decision.get(
                "insufficient_layers",
                []
            )
        )

        if insufficient_layers:

            print(
                "\nInsufficient Evidence Layers:"
            )

            for layer in insufficient_layers:

                print(
                    "-",
                    layer
                )

    return (
        baseline,
        raw_memory_result,
        ndef_result,
        security_result,
        final_decision,
        journal_state,
        time_evidence,
        verification_report,
        report_path,
    )


# --------------------------------------------------
# MAIN WATCHER
# --------------------------------------------------

def main():

    argument_parser = argparse.ArgumentParser(
        description=(
            "N3 NFC Integrity "
            "Verification System"
        )
    )

    argument_parser.add_argument(
        "mode",
        help=(
            "Operation mode: "
            "ENROLL, VERIFY, or UPDATE"
        )
    )

    args = argument_parser.parse_args()

    mode = normalize_mode(
        args.mode
    )


    # --------------------------------------------------
    # CREATE REQUIRED FOLDERS
    # --------------------------------------------------

    INCOMING_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    FAILED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    # --------------------------------------------------
    # START WATCHER
    # --------------------------------------------------

    print(
        "======================================"
    )

    print(
        "N3 AUTOMATIC SCAN WATCHER"
    )

    print(
        "======================================"
    )

    print(
        "N3 Mode :",
        mode
    )

    print(
        "\nWatching folder:"
    )

    print(
        INCOMING_DIR
    )

    print(
        "\nWaiting for NFC scans..."
    )


    # --------------------------------------------------
    # CONTINUOUS MONITORING LOOP
    # --------------------------------------------------

    while True:

        nfc_files = list(
            INCOMING_DIR.glob(
                "*.nfc"
            )
        )

        for file_path in nfc_files:

            try:

                print(
                    "\nChecking whether "
                    "file is ready..."
                )

                if not wait_until_file_ready(
                    file_path
                ):

                    print(
                        "File is not ready yet."
                    )

                    print(
                        "Waiting for next check..."
                    )

                    continue

                print(
                    "File is ready."
                )

                (
                    canonical_scan,
                    quality_result,
                ) = process_scan(
                    file_path
                )


                # --------------------------------------------------
                # COMPLETE EVIDENCE
                # --------------------------------------------------

                if quality_result[
                    "is_complete"
                ]:

                    if mode == "ENROLL":

                        print(
                            "\nEvidence Status:"
                            " READY FOR ENROLLMENT"
                        )

                        handle_enrollment(
                            canonical_scan,
                            file_path
                        )

                    elif mode == "VERIFY":

                        print(
                            "\nEvidence Status:"
                            " READY FOR VERIFICATION"
                        )

                        handle_verification(
                            canonical_scan
                        )

                    elif mode == "UPDATE":

                        print(
                            "\nEvidence Status:"
                            " READY FOR AUTHORIZED UPDATE"
                        )

                        handle_authorized_update(
                            canonical_scan,
                            file_path
                        )


                # --------------------------------------------------
                # INSUFFICIENT EVIDENCE
                # --------------------------------------------------

                else:

                    print(
                        "\nEvidence Status:"
                        " INSUFFICIENT EVIDENCE"
                    )

                    if mode == "ENROLL":

                        print(
                            "Trusted baseline "
                            "will NOT be created."
                        )

                    elif mode == "UPDATE":

                        print(
                            "Authorized baseline update "
                            "will NOT be created."
                        )

                    elif mode == "VERIFY":

                        unknown_decision = (
                            make_unknown_decision(
                                reason=(
                                    "The current NFC scan "
                                    "does not contain enough "
                                    "complete evidence for "
                                    "reliable verification."
                                ),
                                insufficient_area=(
                                    "SCAN_QUALITY"
                                )
                            )
                        )

                        unknown_report = (
                            generate_unknown_report(
                                canonical_scan,
                                quality_result,
                                unknown_decision,
                            )
                        )

                        unknown_report_path = (
                            save_verification_report(
                                unknown_report
                            )
                        )

                        save_verification_to_journal(
                            unknown_report,
                            unknown_report_path
                        )

                        print(
                            "\n======================================"
                        )

                        print(
                            "N3 FINAL VERDICT"
                        )

                        print(
                            "======================================"
                        )

                        print(
                            "Verdict :",
                            unknown_decision[
                                "verdict"
                            ]
                        )

                        print(
                            "Reason  :",
                            unknown_decision[
                                "reason"
                            ]
                        )

                        print(
                            "\nInsufficient Evidence:"
                        )

                        for area in unknown_decision[
                            "insufficient_layers"
                        ]:

                            print(
                                "-",
                                area
                            )

                        print(
                            "\n--- STRUCTURED UNKNOWN REPORT ---"
                        )

                        print(
                            "Scan ID :",
                            unknown_report[
                                "scan_id"
                            ]
                        )

                        print(
                            "Verification Time :",
                            unknown_report[
                                "verification_time_utc"
                            ]
                        )

                        print(
                            "Report Status : GENERATED"
                        )

                        print(
                            "UNKNOWN Report Stored :",
                            unknown_report_path
                        )


                # --------------------------------------------------
                # ARCHIVE ACQUISITION
                # --------------------------------------------------

                move_to_processed(
                    file_path
                )

                print(
                    "\nWaiting for NFC scans..."
                )


            # --------------------------------------------------
            # BASELINE FILE ALREADY EXISTS
            # --------------------------------------------------

            except FileExistsError as error:

                print(
                    "\n======================================"
                )

                print(
                    "BASELINE WRITE REJECTED"
                )

                print(
                    "======================================"
                )

                print(
                    "Mode   :",
                    mode
                )

                print(
                    "File   :",
                    file_path.name
                )

                print(
                    "Reason :",
                    error
                )

                print(
                    "Existing trusted baseline "
                    "was not overwritten."
                )

                move_to_processed(
                    file_path
                )

                print(
                    "\nWaiting for NFC scans..."
                )


            # --------------------------------------------------
            # PROCESSING FAILURE
            # --------------------------------------------------

            except Exception as error:

                print(
                    "\n======================================"
                )

                print(
                    "ERROR PROCESSING NFC SCAN"
                )

                print(
                    "======================================"
                )

                print(
                    "File  :",
                    file_path.name
                )

                print(
                    "Error :",
                    error
                )

                move_to_failed(
                    file_path
                )

                print(
                    "\nWaiting for NFC scans..."
                )

        time.sleep(
            CHECK_INTERVAL
        )


# --------------------------------------------------
# START PROGRAM
# --------------------------------------------------

if __name__ == "__main__":
    main()
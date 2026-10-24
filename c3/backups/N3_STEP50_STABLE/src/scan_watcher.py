from pathlib import Path

import time
import shutil
import argparse


# --------------------------------------------------
# N3 CORE MODULES
# --------------------------------------------------

from parser import parse_flipper_nfc

from canonicalizer import canonicalize_scan

from scan_quality import assess_scan_quality

from mode_manager import normalize_mode


# --------------------------------------------------
# BASELINE MODULES
# --------------------------------------------------

from baseline_manager import (
    build_baseline,
    save_baseline,
    load_baseline,
)

from baseline_version_manager import (
    get_latest_baseline_version,
    get_active_baseline_version,
)

from authorized_update_manager import (
    create_authorized_baseline_update,
)


# --------------------------------------------------
# VERIFICATION MODULES
# --------------------------------------------------

from verifier import (
    verify_raw_memory,
    verify_ndef_application,
    verify_security_state,
)

from ndef_parser import (
    extract_ndef_evidence,
)

from security_state import (
    extract_security_state,
)

from decision_engine import (
    make_final_decision,
    make_unknown_decision,
)

from region_mapper import (
    add_regions_to_raw_changes,
)

from tamper_classifier import (
    classify_change,
)


# --------------------------------------------------
# REPORT / JOURNAL MODULES
# --------------------------------------------------

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


# --------------------------------------------------
# SUPPORT MODULES
# --------------------------------------------------

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

PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

INCOMING_DIR = (
    PROJECT_ROOT
    / "data"
    / "incoming"
)

PROCESSED_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
)

FAILED_DIR = (
    PROJECT_ROOT
    / "data"
    / "failed"
)

CHECK_INTERVAL = 0.2


# ==================================================
# FILE-READY CHECK
# ==================================================

def wait_until_file_ready(
    file_path,
    timeout=15
):
    """
    Wait until an NFC file has completely
    finished writing before N3 parses it.
    """

    start_time = time.time()

    previous_size = -1

    stable_count = 0


    while (
        time.time()
        - start_time
        < timeout
    ):

        try:

            current_size = (
                file_path.stat().st_size
            )

            with file_path.open(
                "rb"
            ) as file:

                file.read(1)


            if (
                current_size
                == previous_size
                and current_size > 0
            ):

                stable_count += 1

                if stable_count >= 2:

                    return True


            else:

                stable_count = 0

                previous_size = (
                    current_size
                )


        except (
            PermissionError,
            OSError,
        ):

            stable_count = 0


        time.sleep(0.1)


    return False


# ==================================================
# CARD IDENTITY HELPER
# ==================================================

def get_baseline_lookup_identity(
    canonical_scan
):
    """
    Return the best family-aware identity
    for trusted-baseline lookup.

    Preferred:
        card_family

    Fallback:
        card_type
    """

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    return (
        card_info.get(
            "card_family"
        )
        or
        card_info.get(
            "card_type"
        )
    )


# ==================================================
# DISPLAY PARSER INFORMATION
# ==================================================

def print_parser_information(
    card_info,
    memory_units
):
    """
    Print family-aware parser information.
    """

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
        "Card Family :",
        card_info.get(
            "N3 card family"
        )
    )


    print(
        "UID         :",
        card_info.get(
            "UID"
        )
    )


    print(
        "ATQA        :",
        card_info.get(
            "ATQA"
        )
    )


    print(
        "SAK         :",
        card_info.get(
            "SAK"
        )
    )


    card_family = card_info.get(
        "N3 card family"
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        print(
            "Card Type   :",
            card_info.get(
                "NTAG/Ultralight type"
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
            len(
                memory_units
            )
        )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        print(
            "Card Type   :",
            "MIFARE Classic 1K"
        )

        print(
            "Classic Type:",
            card_info.get(
                "Mifare Classic type"
            )
        )

        print(
            "Expected Sectors:",
            card_info.get(
                "N3 expected sectors"
            )
        )

        print(
            "Expected Blocks :",
            card_info.get(
                "N3 expected blocks"
            )
        )

        print(
            "Parsed Blocks   :",
            len(
                memory_units
            )
        )


    # --------------------------------------------------
    # UNKNOWN FAMILY
    # --------------------------------------------------

    else:

        print(
            "Parsed Memory Units:",
            len(
                memory_units
            )
        )


    print(
        "\nParser Result: SUCCESS"
    )


# ==================================================
# DISPLAY CANONICAL INFORMATION
# ==================================================

def print_canonical_information(
    canonical_scan
):
    """
    Print family-aware canonicalization result.
    """

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    card_family = card_info.get(
        "card_family"
    )


    print(
        "\n--- CANONICALIZATION ---"
    )


    print(
        "Canonical Family :",
        card_family
    )


    print(
        "Canonical Type   :",
        card_info.get(
            "card_type"
        )
    )


    print(
        "Canonical UID    :",
        card_info.get(
            "uid"
        )
    )


    print(
        "Memory Unit      :",
        card_info.get(
            "memory_unit"
        )
    )


    if card_family == "NTAG215":

        print(
            "Canonical Pages :",
            len(
                canonical_scan.get(
                    "memory_pages",
                    {}
                )
            )
        )


    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        print(
            "Canonical Blocks:",
            len(
                canonical_scan.get(
                    "memory_blocks",
                    {}
                )
            )
        )


    print(
        "\nCanonicalizer Result: SUCCESS"
    )


# ==================================================
# DISPLAY APPLICATION EVIDENCE
# ==================================================

def print_application_evidence(
    canonical_scan,
    application_evidence
):
    """
    Display family-specific application evidence.
    """

    card_family = (
        canonical_scan.get(
            "card_info",
            {}
        ).get(
            "card_family"
        )
    )


    print(
        "\n--- APPLICATION / NDEF EVIDENCE ---"
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        print(
            "Application Type : NDEF"
        )

        print(
            "NDEF Present     :",
            application_evidence.get(
                "ndef_present"
            )
        )


        record = application_evidence.get(
            "record"
        )


        if record:

            print(
                "Record Type      :",
                record.get(
                    "record_type"
                )
            )

            print(
                "Language         :",
                record.get(
                    "language"
                )
            )

            print(
                "Encoding         :",
                record.get(
                    "encoding"
                )
            )

            print(
                "Text             :",
                record.get(
                    "text"
                )
            )


        else:

            print(
                "No supported NDEF Text Record found."
            )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        print(
            "Application Type :",
            application_evidence.get(
                "application_evidence_type"
            )
        )

        print(
            "Application Present:",
            application_evidence.get(
                "application_present"
            )
        )

        print(
            "Marker Count       :",
            application_evidence.get(
                "marker_count"
            )
        )

        print(
            "NDEF Present       :",
            application_evidence.get(
                "ndef_present"
            )
        )


        marker = application_evidence.get(
            "primary_marker"
        )


        if marker:

            print(
                "Sector Number     :",
                marker.get(
                    "sector_number"
                )
            )

            print(
                "Block Number      :",
                marker.get(
                    "block_number"
                )
            )

            print(
                "Block Type        :",
                marker.get(
                    "block_type"
                )
            )

            print(
                "Application Text  :",
                marker.get(
                    "text"
                )
            )


        else:

            print(
                "No controlled N3 MIFARE marker found."
            )


    # --------------------------------------------------
    # UNSUPPORTED FAMILY
    # --------------------------------------------------

    else:

        print(
            "Application Evidence:",
            application_evidence
        )


# ==================================================
# DISPLAY SECURITY EVIDENCE
# ==================================================

def print_security_evidence(
    canonical_scan,
    security_state
):
    """
    Display family-aware security-state evidence.
    """

    card_family = (
        canonical_scan.get(
            "card_info",
            {}
        ).get(
            "card_family"
        )
    )


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


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if (
        card_family == "NTAG215"
        and security_state.get(
            "evidence_complete"
        )
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


        configuration = (
            security_state.get(
                "configuration",
                {}
            )
        )


        print(
            "AUTH0 Page          :",
            configuration.get(
                "auth0_page"
            )
        )

        print(
            "AUTH0 Hex           :",
            configuration.get(
                "auth0_hex"
            )
        )

        print(
            "Protection Enabled  :",
            configuration.get(
                "password_protection_enabled"
            )
        )

        print(
            "Protection Mode     :",
            configuration.get(
                "protection_mode"
            )
        )

        print(
            "Configuration Lock  :",
            configuration.get(
                "configuration_locked"
            )
        )

        print(
            "Authentication Lim  :",
            configuration.get(
                "auth_limit"
            )
        )

        print(
            "NFC Counter Enabled :",
            configuration.get(
                "nfc_counter_enabled"
            )
        )

        print(
            "Counter PWD Protect :",
            configuration.get(
                "nfc_counter_password_protected"
            )
        )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
        and security_state.get(
            "evidence_complete"
        )
    ):

        print(
            "Expected Sectors    :",
            security_state.get(
                "expected_sector_count"
            )
        )

        print(
            "Security Sectors    :",
            security_state.get(
                "parsed_security_sectors"
            )
        )

        print(
            "Missing Trailers    :",
            security_state.get(
                "missing_sector_trailer_blocks"
            )
        )

        print(
            "Malformed Trailers  :",
            security_state.get(
                "malformed_sector_trailer_blocks"
            )
        )

        print(
            "Key Storage Policy  :",
            security_state.get(
                "key_storage_policy"
            )
        )

        print(
            "Sensitive Keys Stored:",
            security_state.get(
                "sensitive_credentials_stored"
            )
        )


    # --------------------------------------------------
    # INCOMPLETE EVIDENCE
    # --------------------------------------------------

    else:

        if security_state.get(
            "missing_pages"
        ):

            print(
                "Missing Pages:",
                security_state.get(
                    "missing_pages"
                )
            )


        if security_state.get(
            "missing_sector_trailer_blocks"
        ):

            print(
                "Missing Sector Trailers:",
                security_state.get(
                    "missing_sector_trailer_blocks"
                )
            )


        if security_state.get(
            "malformed_sector_trailer_blocks"
        ):

            print(
                "Malformed Sector Trailers:",
                security_state.get(
                    "malformed_sector_trailer_blocks"
                )
            )


        if security_state.get(
            "reason"
        ):

            print(
                "Reason:",
                security_state.get(
                    "reason"
                )
            )


# ==================================================
# DISPLAY SCAN QUALITY
# ==================================================

def print_scan_quality(
    quality_result
):
    """
    Display family-aware scan-quality result.
    """

    print(
        "\n--- SCAN QUALITY ---"
    )


    print(
        "Card Family    :",
        quality_result.get(
            "card_family"
        )
    )

    print(
        "Card Type      :",
        quality_result.get(
            "card_type"
        )
    )

    print(
        "UID            :",
        quality_result.get(
            "uid"
        )
    )

    print(
        "Memory Unit    :",
        quality_result.get(
            "memory_unit"
        )
    )

    print(
        "Quality Status :",
        quality_result.get(
            "quality_status"
        )
    )


    card_family = quality_result.get(
        "card_family"
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        print(
            "Pages Total    :",
            quality_result.get(
                "pages_total"
            )
        )

        print(
            "Pages Read     :",
            quality_result.get(
                "pages_read"
            )
        )

        print(
            "Parsed Pages   :",
            quality_result.get(
                "parsed_pages"
            )
        )

        print(
            "Missing Pages  :",
            quality_result.get(
                "missing_pages",
                []
            )
        )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        print(
            "Blocks Total   :",
            quality_result.get(
                "blocks_total"
            )
        )

        print(
            "Sectors Total  :",
            quality_result.get(
                "sectors_total"
            )
        )

        print(
            "Parsed Blocks  :",
            quality_result.get(
                "parsed_blocks"
            )
        )

        print(
            "Missing Blocks :",
            quality_result.get(
                "missing_blocks",
                []
            )
        )

        print(
            "Malformed Blocks:",
            quality_result.get(
                "malformed_blocks",
                []
            )
        )


    print(
        "Unknown Bytes  :",
        quality_result.get(
            "unknown_byte_count"
        )
    )


    reasons = quality_result.get(
        "reasons",
        []
    )


    if reasons:

        print(
            "\nQuality Issues:"
        )

        for reason in reasons:

            print(
                "-",
                reason
            )


    print(
        "\nScan Quality Result:",
        quality_result.get(
            "quality_status"
        )
    )


# ==================================================
# PROCESS NEW NFC SCAN
# ==================================================

def process_scan(
    file_path
):
    """
    Parse and prepare one NFC acquisition.

    Automatically supports:

    - NTAG215
    - MIFARE Classic 1K
    """

    print(
        "\n======================================"
    )

    print(
        "NEW NFC SCAN DETECTED"
    )

    print(
        "======================================"
    )


    print(
        "File :",
        file_path.name
    )


    # --------------------------------------------------
    # STEP 1: PARSE NFC FILE
    # --------------------------------------------------

    card_info, memory_units = (
        parse_flipper_nfc(
            file_path
        )
    )


    print_parser_information(
        card_info,
        memory_units
    )


    # --------------------------------------------------
    # STEP 2: CANONICALIZE
    # --------------------------------------------------

    canonical_scan = (
        canonicalize_scan(
            card_info,
            memory_units
        )
    )


    print_canonical_information(
        canonical_scan
    )


    # --------------------------------------------------
    # STEP 3: READER METADATA
    # --------------------------------------------------

    reader_metadata = (
        build_reader_metadata(
            source_file=file_path.name,
            reader_name="Flipper Zero",
            acquisition_method="NFC_DUMP_FILE",
            interface_type="FILE_IMPORT",
        )
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
    # STEP 4: APPLICATION EVIDENCE
    # --------------------------------------------------

    application_evidence = (
        extract_ndef_evidence(
            canonical_scan
        )
    )


    canonical_scan[
        "ndef_evidence"
    ] = application_evidence


    print_application_evidence(
        canonical_scan,
        application_evidence
    )


    # --------------------------------------------------
    # STEP 5: SECURITY EVIDENCE
    # --------------------------------------------------

    security_state = (
        extract_security_state(
            canonical_scan
        )
    )


    canonical_scan[
        "security_state"
    ] = security_state


    print_security_evidence(
        canonical_scan,
        security_state
    )


    # --------------------------------------------------
    # STEP 6: SCAN QUALITY
    # --------------------------------------------------

    quality_result = (
        assess_scan_quality(
            canonical_scan
        )
    )


    print_scan_quality(
        quality_result
    )


    return (
        canonical_scan,
        quality_result,
    )


# ==================================================
# UNIQUE DESTINATION HELPER
# ==================================================

def build_unique_destination(
    destination_directory,
    file_path
):
    """
    Prevent processed/failed files from
    overwriting previous acquisitions.
    """

    destination = (
        destination_directory
        / file_path.name
    )


    if not destination.exists():

        return destination


    timestamp = time.strftime(
        "%Y%m%d_%H%M%S"
    )


    destination = (
        destination_directory
        /
        (
            f"{file_path.stem}_"
            f"{timestamp}"
            f"{file_path.suffix}"
        )
    )


    counter = 1


    while destination.exists():

        destination = (
            destination_directory
            /
            (
                f"{file_path.stem}_"
                f"{timestamp}_"
                f"{counter}"
                f"{file_path.suffix}"
            )
        )

        counter += 1


    return destination


# ==================================================
# MOVE PROCESSED FILE
# ==================================================

def move_to_processed(
    file_path
):
    """
    Move successfully handled acquisition
    into the processed directory.
    """

    destination = (
        build_unique_destination(
            PROCESSED_DIR,
            file_path
        )
    )


    shutil.move(
        str(file_path),
        str(destination)
    )


    print(
        "\nStored In :",
        destination
    )


# ==================================================
# MOVE FAILED FILE
# ==================================================

def move_to_failed(
    file_path
):
    """
    Move acquisition that could not be
    processed into the failed directory.
    """

    destination = (
        build_unique_destination(
            FAILED_DIR,
            file_path
        )
    )


    shutil.move(
        str(file_path),
        str(destination)
    )


    print(
        "\nFailed Scan Stored In :",
        destination
    )


# ==================================================
# HANDLE ENROLL MODE
# ==================================================

def handle_enrollment(
    canonical_scan,
    file_path
):
    """
    Create V1 trusted baseline for either
    NTAG215 or MIFARE Classic 1K.
    """

    print(
        "\n--- TRUSTED BASELINE ENROLLMENT ---"
    )


    card_info = canonical_scan.get(
        "card_info",
        {}
    )


    baseline = build_baseline(
        canonical_scan,
        file_path,
        version=1
    )


    baseline_path = save_baseline(
        baseline
    )


    integrity_event = (
        save_integrity_event(

            event_type="ENROLLMENT",

            card_type=card_info.get(
                "card_type"
            ),

            uid=card_info.get(
                "uid"
            ),

            new_version=baseline.get(
                "baseline_version"
            ),

            new_baseline_path=baseline_path,

            previous_version=None,

            previous_baseline_path=None,

            authorization_status="AUTHORIZED",

            details={
                "source_file":
                    file_path.name,

                "card_family":
                    card_info.get(
                        "card_family"
                    ),
            },
        )
    )


    print(
        "Card Family       :",
        card_info.get(
            "card_family"
        )
    )

    print(
        "Card Type         :",
        card_info.get(
            "card_type"
        )
    )

    print(
        "UID               :",
        card_info.get(
            "uid"
        )
    )

    print(
        "Baseline Version  :",
        baseline.get(
            "baseline_version"
        )
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
        integrity_event.get(
            "event_id"
        )
    )

    print(
        "Journal Status    : RECORDED"
    )


# ==================================================
# HANDLE AUTHORIZED UPDATE
# ==================================================

def handle_authorized_update(
    canonical_scan,
    file_path
):
    """
    Create a new authorized trusted-baseline
    version for the current card.
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


    card_family = (
        canonical_scan.get(
            "card_info",
            {}
        ).get(
            "card_family"
        )
    )


    integrity_event = (
        save_integrity_event(

            event_type="AUTHORIZED_UPDATE",

            card_type=update_result.get(
                "card_type"
            ),

            uid=update_result.get(
                "uid"
            ),

            previous_version=(
                update_result.get(
                    "previous_version"
                )
            ),

            new_version=(
                update_result.get(
                    "new_version"
                )
            ),

            previous_baseline_path=(
                update_result.get(
                    "previous_baseline_path"
                )
            ),

            new_baseline_path=(
                update_result.get(
                    "new_baseline_path"
                )
            ),

            authorization_status="AUTHORIZED",

            details={
                "source_file":
                    file_path.name,

                "card_family":
                    card_family,
            },
        )
    )


    print(
        "Card Family       :",
        card_family
    )

    print(
        "Card Type         :",
        update_result.get(
            "card_type"
        )
    )

    print(
        "UID               :",
        update_result.get(
            "uid"
        )
    )

    print(
        "Previous Version  :",
        update_result.get(
            "previous_version"
        )
    )

    print(
        "New Version       :",
        update_result.get(
            "new_version"
        )
    )

    print(
        "Previous Baseline :",
        update_result.get(
            "previous_baseline_path"
        )
    )

    print(
        "New Baseline      :",
        update_result.get(
            "new_baseline_path"
        )
    )

    print(
        "Integrity Event ID:",
        integrity_event.get(
            "event_id"
        )
    )

    print(
        "Journal Status    : RECORDED"
    )

    print(
        "Update Result     : SUCCESS"
    )


# ==================================================
# DISPLAY RAW VERIFICATION RESULT
# ==================================================

def print_raw_verification(
    card_family,
    raw_memory_result
):
    """
    Print family-specific raw-memory changes.
    """

    print(
        "\n--- RAW MEMORY VERIFICATION ---"
    )

    print(
        "Status :",
        raw_memory_result.get(
            "status"
        )
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        print(
            "Changed Page Count :",
            raw_memory_result.get(
                "changed_page_count",
                0
            )
        )


        changed_pages = (
            raw_memory_result.get(
                "changed_pages",
                []
            )
        )


        if changed_pages:

            print(
                "\nChanged Pages:"
            )


            for change in changed_pages:

                print(
                    f"Page {change.get('page')}:"
                )

                print(
                    "  Region    :",
                    change.get(
                        "region"
                    )
                )

                print(
                    "  Old Value :",
                    change.get(
                        "old_value"
                    )
                )

                print(
                    "  New Value :",
                    change.get(
                        "new_value"
                    )
                )


        else:

            print(
                "No raw page changes detected."
            )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        print(
            "Changed Block Count:",
            raw_memory_result.get(
                "changed_block_count",
                0
            )
        )


        changed_blocks = (
            raw_memory_result.get(
                "changed_blocks",
                []
            )
        )


        if changed_blocks:

            print(
                "\nChanged Blocks:"
            )


            for change in changed_blocks:

                print(
                    f"Sector "
                    f"{change.get('sector_number')} "
                    f"/ Block "
                    f"{change.get('block_number')}:"
                )

                print(
                    "  Block Type :",
                    change.get(
                        "block_type"
                    )
                )

                print(
                    "  Region     :",
                    change.get(
                        "region"
                    )
                )

                print(
                    "  Old Value  :",
                    change.get(
                        "old_value"
                    )
                )

                print(
                    "  New Value  :",
                    change.get(
                        "new_value"
                    )
                )


        else:

            print(
                "No raw block changes detected."
            )


# ==================================================
# DISPLAY APPLICATION VERIFICATION
# ==================================================

def print_application_verification(
    ndef_result
):
    """
    Print application-layer verification result.
    """

    print(
        "\n--- APPLICATION / NDEF VERIFICATION ---"
    )


    print(
        "Application Type    :",
        ndef_result.get(
            "application_type"
        )
    )

    print(
        "Status              :",
        ndef_result.get(
            "status"
        )
    )

    print(
        "Changed Field Count :",
        ndef_result.get(
            "changed_field_count",
            0
        )
    )


    changed_fields = (
        ndef_result.get(
            "changed_fields",
            []
        )
    )


    if changed_fields:

        print(
            "\nChanged Application Fields:"
        )


        for change in changed_fields:

            print(
                "Field:",
                change.get(
                    "field"
                )
            )


            if (
                change.get(
                    "sector_number"
                )
                is not None
            ):

                print(
                    "  Sector :",
                    change.get(
                        "sector_number"
                    )
                )


            if (
                change.get(
                    "block_number"
                )
                is not None
            ):

                print(
                    "  Block  :",
                    change.get(
                        "block_number"
                    )
                )


            print(
                "  Old Value :",
                change.get(
                    "old_value"
                )
            )

            print(
                "  New Value :",
                change.get(
                    "new_value"
                )
            )


    else:

        print(
            "No application changes detected."
        )


# ==================================================
# DISPLAY SECURITY VERIFICATION
# ==================================================

def print_security_verification(
    security_result
):
    """
    Print security-layer verification result.
    """

    print(
        "\n--- SECURITY-STATE VERIFICATION ---"
    )


    print(
        "Status              :",
        security_result.get(
            "status"
        )
    )

    print(
        "Changed Field Count :",
        security_result.get(
            "changed_field_count",
            0
        )
    )


    changed_fields = (
        security_result.get(
            "changed_fields",
            []
        )
    )


    if changed_fields:

        print(
            "\nChanged Security Fields:"
        )


        for change in changed_fields:

            print(
                "Field:",
                change.get(
                    "field"
                )
            )


            if (
                change.get(
                    "sector_number"
                )
                is not None
            ):

                print(
                    "  Sector :",
                    change.get(
                        "sector_number"
                    )
                )


            if (
                change.get(
                    "sector_trailer_block"
                )
                is not None
            ):

                print(
                    "  Trailer Block :",
                    change.get(
                        "sector_trailer_block"
                    )
                )


            print(
                "  Old Value :",
                change.get(
                    "old_value"
                )
            )

            print(
                "  New Value :",
                change.get(
                    "new_value"
                )
            )


    elif security_result.get(
        "reason"
    ):

        print(
            "Reason :",
            security_result.get(
                "reason"
            )
        )


    else:

        print(
            "No security-state changes detected."
        )


# ==================================================
# HANDLE VERIFY MODE
# ==================================================

def handle_verification(
    canonical_scan,
    quality_result
):
    """
    Perform complete family-aware verification
    against the currently active trusted baseline.

    If the card has no active trusted baseline,
    generate a structured UNKNOWN report instead
    of failing the verification flow.
    """

    verification_timer = (
        start_timer()
    )


    print(
        "\n--- VERIFICATION MODE ---"
    )


    card_info = canonical_scan.get(
        "card_info",
        {}
    )


    card_family = card_info.get(
        "card_family"
    )

    card_type = card_info.get(
        "card_type"
    )

    uid = card_info.get(
        "uid"
    )


    baseline_identity = (
        get_baseline_lookup_identity(
            canonical_scan
        )
    )


    print(
        "Card Family :",
        card_family
    )

    print(
        "Card Type   :",
        card_type
    )

    print(
        "UID         :",
        uid
    )


    # --------------------------------------------------
    # FIND STORED + ACTIVE TRUSTED BASELINE
    # --------------------------------------------------

    latest_version = (
        get_latest_baseline_version(
            baseline_identity,
            uid
        )
    )


    active_version = (
        get_active_baseline_version(
            baseline_identity,
            uid
        )
    )


    # --------------------------------------------------
    # NO ACTIVE TRUSTED BASELINE
    # --------------------------------------------------

    if active_version is None:

        print()
        print(
            "--- TRUSTED BASELINE LOOKUP ---"
        )

        print(
            "Status : NOT_FOUND"
        )

        print(
            "Reason : No trusted baseline exists "
            "for this NFC card."
        )


        # --------------------------------------------------
        # CREATE UNKNOWN DECISION
        # --------------------------------------------------

        unknown_decision = (
            make_unknown_decision(
                reason=(
                    "No trusted baseline exists for "
                    "this NFC card. Integrity verification "
                    "cannot be performed until the card "
                    "is enrolled."
                ),
                insufficient_area=(
                    "TRUSTED_BASELINE"
                ),
            )
        )


        # --------------------------------------------------
        # CREATE STRUCTURED UNKNOWN REPORT
        # --------------------------------------------------

        unknown_report = (
            generate_unknown_report(
                canonical_scan,
                quality_result,
                unknown_decision,
            )
        )


        # --------------------------------------------------
        # BASELINE STATE
        # --------------------------------------------------

        unknown_report[
            "baseline"
        ] = {
            "baseline_identity":
                baseline_identity,

            "baseline_version":
                None,

            "enrollment_time_utc":
                None,

            "source_file":
                None,
        }


        # --------------------------------------------------
        # VERIFICATION LAYERS WERE NOT EVALUATED
        # --------------------------------------------------

        unknown_report[
            "application_ndef"
        ] = {
            "card_family":
                card_family,

            "application_type":
                None,

            "status":
                "NOT_EVALUATED",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "No trusted baseline is available."
                ),
        }


        unknown_report[
            "raw_memory"
        ] = {
            "card_family":
                card_family,

            "memory_unit":
                card_info.get(
                    "memory_unit"
                ),

            "status":
                "NOT_EVALUATED",

            "changed_page_count":
                0,

            "changed_pages":
                [],

            "changed_block_count":
                0,

            "changed_blocks":
                [],

            "reason":
                (
                    "No trusted baseline is available."
                ),
        }


        unknown_report[
            "security_state"
        ] = {
            "card_family":
                card_family,

            "status":
                "NOT_EVALUATED",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "No trusted baseline is available."
                ),
        }


        # --------------------------------------------------
        # ROLLBACK CANNOT BE EVALUATED
        # --------------------------------------------------

        unknown_rollback_evidence = {
            "rollback_status":
                "NOT_EVALUATED",

            "rollback_detected":
                False,

            "matched_older_version":
                None,

            "latest_authorized_version":
                latest_version,

            "active_baseline_version":
                None,

            "checked_older_versions":
                [],

            "reason":
                (
                    "Rollback cannot be evaluated "
                    "because no active trusted baseline "
                    "exists for this NFC card."
                ),
        }


        unknown_report[
            "rollback_evidence"
        ] = (
            unknown_rollback_evidence
        )


        # --------------------------------------------------
        # JOURNAL STATE
        # --------------------------------------------------

        unknown_journal_state = {
            "journal_status":
                (
                    "UNREGISTERED_CARD"
                    if latest_version is None
                    else "NO_ACTIVE_BASELINE"
                ),

            "latest_authorized_version":
                latest_version,

            "baseline_version_used":
                None,

            "rollback_matched_version":
                None,

            "reason":
                (
                    "No trusted baseline exists for "
                    "this NFC card."
                    if latest_version is None
                    else
                    "Stored baseline history exists, "
                    "but no active trusted baseline "
                    "is selected for this NFC card."
                ),
        }


        unknown_report[
            "journal_state"
        ] = (
            unknown_journal_state
        )


        # --------------------------------------------------
        # TAMPER CLASSIFICATION
        # --------------------------------------------------

        unknown_report[
            "tamper_classification"
        ] = [
            "NOT_EVALUATED"
        ]


        # --------------------------------------------------
        # TIME EVIDENCE
        # --------------------------------------------------

        unknown_time_evidence = {
            "status":
                "NOT_EVALUATED",

            "last_known_valid_utc":
                None,

            "last_known_valid_source":
                None,

            "last_known_valid_baseline_version":
                None,

            "first_detected_modified_utc":
                None,

            "possible_modification_window": {
                "start_utc":
                    None,

                "end_utc":
                    None,
            },

            "exact_modification_time_utc":
                None,

            "reason":
                (
                    "Time evidence cannot be established "
                    "because no active trusted baseline "
                    "exists for this NFC card."
                ),
        }


        unknown_report[
            "time_evidence"
        ] = (
            unknown_time_evidence
        )


        # --------------------------------------------------
        # PERFORMANCE METRICS
        # --------------------------------------------------

        unknown_latency_ms = (
            calculate_elapsed_ms(
                verification_timer
            )
        )


        unknown_report[
            "performance_metrics"
        ] = {
            "verification_latency_ms":
                unknown_latency_ms,

            "measurement_scope":
                (
                    "UNKNOWN decision processing from "
                    "verification start until structured "
                    "report preparation, excluding report "
                    "and SQLite persistence."
                ),
        }


        # --------------------------------------------------
        # SAVE STRUCTURED REPORT
        # --------------------------------------------------

        unknown_report_path = (
            save_verification_report(
                unknown_report
            )
        )


        # --------------------------------------------------
        # SAVE SQLITE JOURNAL RECORD
        # --------------------------------------------------

        save_verification_to_journal(
            unknown_report,
            unknown_report_path
        )


        # --------------------------------------------------
        # TERMINAL OUTPUT
        # --------------------------------------------------

        print()
        print(
            "======================================"
        )

        print(
            "N3 FINAL VERDICT"
        )

        print(
            "======================================"
        )

        print(
            "Card Family :",
            card_family
        )

        print(
            "Card Type   :",
            card_type
        )

        print(
            "UID         :",
            uid
        )

        print(
            "Verdict     :",
            unknown_decision.get(
                "verdict"
            )
        )

        print(
            "Reason      :",
            unknown_decision.get(
                "reason"
            )
        )

        print(
            "Baseline    : NOT_FOUND"
        )

        print(
            "Journal     :",
            unknown_journal_state.get(
                "journal_status"
            )
        )

        print(
            "Rollback    :",
            unknown_rollback_evidence.get(
                "rollback_status"
            )
        )

        print(
            "Verification Latency :",
            unknown_latency_ms,
            "ms"
        )

        print(
            "Report      :",
            unknown_report_path
        )

        print()


        # Stop verification here because there is
        # no trusted baseline to compare against.
        return unknown_report


    print(
        "Latest Stored Baseline Version :",
     latest_version
    )

    print(
     "Active Trusted Baseline Version :",
      active_version
    )


# --------------------------------------------------
# LOAD + HMAC VERIFY ACTIVE BASELINE
# --------------------------------------------------

    baseline, baseline_path = (
     load_baseline(
        baseline_identity,
        uid,
        version=active_version
    )
)


    print(
        "\n--- BASELINE INTEGRITY ---"
    )

    print(
        "Baseline HMAC    : VALID"
    )

    print(
        "Baseline Version :",
        baseline.get(
            "baseline_version"
        )
    )

    print(
        "Baseline Loaded  :",
        baseline_path
    )


    # --------------------------------------------------
    # RAW MEMORY VERIFICATION
    # --------------------------------------------------

    raw_memory_result = (
        verify_raw_memory(
            canonical_scan,
            baseline
        )
    )


    raw_memory_result = (
        add_regions_to_raw_changes(
            card_family,
            raw_memory_result
        )
    )


    print_raw_verification(
        card_family,
        raw_memory_result
    )


    # --------------------------------------------------
    # APPLICATION VERIFICATION
    # --------------------------------------------------

    ndef_result = (
        verify_ndef_application(
            canonical_scan,
            baseline
        )
    )


    print_application_verification(
        ndef_result
    )


    # --------------------------------------------------
    # SECURITY VERIFICATION
    # --------------------------------------------------

    security_result = (
        verify_security_state(
            canonical_scan,
            baseline
        )
    )


    print_security_verification(
        security_result
    )


    # --------------------------------------------------
    # FINAL DECISION
    # --------------------------------------------------

    final_decision = (
        make_final_decision(
            raw_memory_result,
            ndef_result,
            security_result
        )
    )


    # --------------------------------------------------
    # ROLLBACK DETECTION
    # --------------------------------------------------

  # --------------------------------------------------
# ROLLBACK DETECTION
# --------------------------------------------------

    if (
        final_decision.get(
            "verdict"
        )
        == "MODIFIED"
    ):

        rollback_result = (
         detect_rollback(

             canonical_scan=(
                canonical_scan
            ),

             card_type=(
                    card_type
              ),

             uid=uid,

              active_baseline_version=(
                active_version
             ),
         )
      )

    # Preserve both concepts separately:
    # latest_version = highest stored/history version
    # active_version = trusted version used for VERIFY

        rollback_result[
          "latest_authorized_version"
        ] = latest_version

        rollback_result[
              "active_baseline_version"
                ] = active_version


    elif (
     final_decision.get(
           "verdict"
     )
        == "VALID"
    ):

        rollback_result = {

         "rollback_status":
                "NOT_REQUIRED",

         "rollback_detected":
                False,

            "matched_older_version":
             None,

         "latest_authorized_version":
                latest_version,

         "active_baseline_version":
              active_version,

            "checked_older_versions":
              [],

            "reason":
             (
                 "Rollback comparison is not required "
                 "because the current NFC state matches "
                 "the currently active trusted baseline."
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

        "active_baseline_version":
            active_version,

        "checked_older_versions":
            [],

        "reason":
            (
                "Rollback comparison was not evaluated "
                "because the verification result does "
                "not provide sufficient confirmed evidence."
            ),
    }

    print(
        "Rollback Status :",
        rollback_result.get(
            "rollback_status"
        )
    )

    print(
        "Rollback Detected :",
        rollback_result.get(
            "rollback_detected"
        )
    )

    print(
        "Matched Older Version :",
        rollback_result.get(
            "matched_older_version"
        )
    )

    print(
        "Latest Authorized Version :",
        rollback_result.get(
            "latest_authorized_version"
        )
    )

    print(
        "Checked Older Versions :",
        rollback_result.get(
            "checked_older_versions"
        )
    )

    print(
        "Reason :",
        rollback_result.get(
            "reason"
        )
    )


    # --------------------------------------------------
    # JOURNAL STATE
    # --------------------------------------------------

    journal_state = (
        evaluate_journal_state(

            card_type=card_type,

            uid=uid,

            baseline_version=(
                baseline.get(
                    "baseline_version"
                )
            ),

            verification_verdict=(
                final_decision.get(
                    "verdict"
                )
            ),
        )
    )


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
        journal_state.get(
            "journal_status"
        )
    )

    print(
        "Reason         :",
        journal_state.get(
            "reason"
        )
    )

    print(
        "Latest Authorized Version :",
        journal_state.get(
            "latest_authorized_version"
        )
    )

    print(
        "Baseline Version Used     :",
        journal_state.get(
            "baseline_version_used"
        )
    )


    if (
        journal_state.get(
            "rollback_matched_version"
        )
        is not None
    ):

        print(
            "Rollback Matched Version :",
            journal_state.get(
                "rollback_matched_version"
            )
        )


    # --------------------------------------------------
    # CHANGE CLASSIFICATION
    # --------------------------------------------------

    tamper_classes = (
        classify_change(
            raw_memory_result,
            ndef_result,
            security_result
        )
    )


    # --------------------------------------------------
    # STRUCTURED REPORT
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

            journal_state=(
                journal_state
            ),
        )
    )


    verification_report[
        "rollback_evidence"
    ] = rollback_result


    # --------------------------------------------------
    # TIME EVIDENCE
    # --------------------------------------------------

    time_evidence = (
        build_time_evidence(

            card_type=card_type,

            uid=uid,

            current_verdict=(
                final_decision.get(
                    "verdict"
                )
            ),

            current_verification_time_utc=(
                verification_report.get(
                    "verification_time_utc"
                )
            ),

            current_scan_id=(
                verification_report.get(
                    "scan_id"
                )
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
    )


    verification_report[
        "time_evidence"
    ] = time_evidence


    print(
        "\n--- TIME EVIDENCE ---"
    )

    print(
        "Status :",
        time_evidence.get(
            "status"
        )
    )

    print(
        "Last Known Valid :",
        time_evidence.get(
            "last_known_valid_utc"
        )
    )

    print(
        "Last Known Valid Source :",
        time_evidence.get(
            "last_known_valid_source"
        )
    )

    print(
        "Last Known Valid Baseline Version :",
        time_evidence.get(
            "last_known_valid_baseline_version"
        )
    )

    print(
        "First Detected Modified :",
        time_evidence.get(
            "first_detected_modified_utc"
        )
    )


    modification_window = (
        time_evidence.get(
            "possible_modification_window"
        )
        or {}
    )


    print(
        "Possible Window Start :",
        modification_window.get(
            "start_utc"
        )
    )

    print(
        "Possible Window End   :",
        modification_window.get(
            "end_utc"
        )
    )

    print(
        "Exact Modification Time :",
        time_evidence.get(
            "exact_modification_time_utc"
        )
    )

    print(
        "Reason :",
        time_evidence.get(
            "reason"
        )
    )


    # --------------------------------------------------
    # PERFORMANCE METRICS
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
    # SAVE REPORT
    # --------------------------------------------------

    report_path = (
        save_verification_report(
            verification_report
        )
    )


    # --------------------------------------------------
    # SAVE SQLITE VERIFICATION EVENT
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
        "Card Family :",
        card_family
    )

    print(
        "Card Type   :",
        card_type
    )

    print(
        "UID         :",
        uid
    )

    print(
        "Verdict :",
        final_decision.get(
            "verdict"
        )
    )

    print(
        "Reason  :",
        final_decision.get(
            "reason"
        )
    )

    print(
        "Rollback Status :",
        rollback_result.get(
            "rollback_status"
        )
    )

    print(
        "Rollback Detected :",
        rollback_result.get(
            "rollback_detected"
        )
    )

    print(
        "Journal Status :",
        journal_state.get(
            "journal_status"
        )
    )


    if (
        journal_state.get(
            "rollback_matched_version"
        )
        is not None
    ):

        print(
            "Rollback Matched Version :",
            journal_state.get(
                "rollback_matched_version"
            )
        )


    print(
        "Time Evidence Status :",
        time_evidence.get(
            "status"
        )
    )

    print(
        "Verification Latency :",
        verification_latency_ms,
        "ms"
    )


    print(
        "\nLayer Results:"
    )


    for layer, status in (
        final_decision.get(
            "layer_statuses",
            {}
        ).items()
    ):

        print(
            f"{layer} : {status}"
        )


    print(
        "\nTamper Classification:"
    )


    for tamper_class in (
        tamper_classes
    ):

        print(
            "-",
            tamper_class
        )


    print(
        "\n--- STRUCTURED VERIFICATION REPORT ---"
    )

    print(
        "Scan ID :",
        verification_report.get(
            "scan_id"
        )
    )

    print(
        "Verification Time :",
        verification_report.get(
            "verification_time_utc"
        )
    )

    print(
        "Baseline Version Used :",
        baseline.get(
            "baseline_version"
        )
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


    if (
        final_decision.get(
            "verdict"
        )
        == "MODIFIED"
    ):

        changed_layers = (
            final_decision.get(
                "changed_layers",
                []
            )
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


    if (
        final_decision.get(
            "verdict"
        )
        == "UNKNOWN"
    ):

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

            for layer in (
                insufficient_layers
            ):

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


# ==================================================
# HANDLE UNKNOWN VERIFY RESULT
# ==================================================

def handle_unknown_verification(
    canonical_scan,
    quality_result
):
    """
    Build and persist a standardized UNKNOWN
    result when scan evidence is incomplete.
    """

    unknown_verification_timer = (
        start_timer()
    )


    # --------------------------------------------------
    # UNKNOWN DECISION
    # --------------------------------------------------

    unknown_decision = (
        make_unknown_decision(

            reason=(
                "The current NFC scan does not "
                "contain enough complete evidence "
                "for reliable verification."
            ),

            insufficient_area=(
                "SCAN_QUALITY"
            ),
        )
    )


    # --------------------------------------------------
    # UNKNOWN REPORT
    # --------------------------------------------------

    unknown_report = (
        generate_unknown_report(
            canonical_scan,
            quality_result,
            unknown_decision,
        )
    )


    # --------------------------------------------------
    # CARD IDENTITY
    # --------------------------------------------------

    unknown_card_info = (
        canonical_scan.get(
            "card_info",
            {}
        )
    )


    unknown_card_type = (
        unknown_card_info.get(
            "card_type"
        )
    )

    unknown_card_family = (
        unknown_card_info.get(
            "card_family"
        )
    )

    unknown_uid = (
        unknown_card_info.get(
            "uid"
        )
    )


    baseline_identity = (
        unknown_card_family
        or unknown_card_type
    )


    if (
        baseline_identity
        and unknown_uid
    ):

        unknown_latest_version = (
            get_latest_baseline_version(
                baseline_identity,
                unknown_uid
            )
        )

    else:

        unknown_latest_version = None


    # --------------------------------------------------
    # UNKNOWN JOURNAL STATE
    # --------------------------------------------------

    unknown_journal_state = {

        "journal_status":
            "INSUFFICIENT_EVIDENCE",

        "reason":
            (
                "Journal-state verification cannot "
                "be completed because the current "
                "NFC scan does not contain enough "
                "complete evidence."
            ),

        "latest_authorized_version":
            unknown_latest_version,

        "baseline_version_used":
            None,

        "rollback_matched_version":
            None,
    }


    unknown_report[
        "journal_state"
    ] = unknown_journal_state


    # --------------------------------------------------
    # UNKNOWN ROLLBACK EVIDENCE
    # --------------------------------------------------

    unknown_rollback_evidence = {

        "rollback_status":
            "NOT_EVALUATED",

        "rollback_detected":
            False,

        "matched_older_version":
            None,

        "latest_authorized_version":
            unknown_latest_version,

        "checked_older_versions":
            [],

        "reason":
            (
                "Rollback comparison was not "
                "evaluated because the current "
                "NFC scan does not contain enough "
                "complete evidence."
            ),
    }


    unknown_report[
        "rollback_evidence"
    ] = unknown_rollback_evidence


    # --------------------------------------------------
    # UNKNOWN TIME EVIDENCE
    # --------------------------------------------------

    unknown_time_evidence = {

        "status":
            "INSUFFICIENT_EVIDENCE",

        "last_known_valid_utc":
            None,

        "last_known_valid_source":
            None,

        "last_known_valid_baseline_version":
            None,

        "first_detected_modified_utc":
            None,

        "possible_modification_window": {

            "start_utc":
                None,

            "end_utc":
                None,
        },

        "exact_modification_time_utc":
            None,

        "reason":
            (
                "Time evidence cannot be established "
                "because the current NFC scan does not "
                "contain enough complete evidence for "
                "reliable integrity verification."
            ),
    }


    unknown_report[
        "time_evidence"
    ] = unknown_time_evidence


    # --------------------------------------------------
    # UNKNOWN LATENCY
    # --------------------------------------------------

    unknown_latency_ms = (
        calculate_elapsed_ms(
            unknown_verification_timer
        )
    )


    unknown_report[
        "performance_metrics"
    ] = {

        "verification_latency_ms":
            unknown_latency_ms,

        "measurement_scope":
            (
                "UNKNOWN decision processing from "
                "scan-quality failure handling until "
                "structured report preparation, "
                "excluding report and SQLite persistence."
            ),
    }


    # --------------------------------------------------
    # SAVE UNKNOWN REPORT
    # --------------------------------------------------

    unknown_report_path = (
        save_verification_report(
            unknown_report
        )
    )


    save_verification_to_journal(
        unknown_report,
        unknown_report_path
    )


    # --------------------------------------------------
    # OUTPUT
    # --------------------------------------------------

    print(
        "\n--- JOURNAL-STATE VERIFICATION ---"
    )

    print(
        "Journal Status :",
        unknown_journal_state.get(
            "journal_status"
        )
    )

    print(
        "Latest Authorized Version :",
        unknown_journal_state.get(
            "latest_authorized_version"
        )
    )


    print(
        "\n--- ROLLBACK DETECTION ---"
    )

    print(
        "Rollback Status :",
        unknown_rollback_evidence.get(
            "rollback_status"
        )
    )

    print(
        "Rollback Detected :",
        unknown_rollback_evidence.get(
            "rollback_detected"
        )
    )


    print(
        "\n--- TIME EVIDENCE ---"
    )

    print(
        "Status :",
        unknown_time_evidence.get(
            "status"
        )
    )


    print(
        "\n--- PERFORMANCE METRICS ---"
    )

    print(
        "Verification Latency :",
        unknown_latency_ms,
        "ms"
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
        unknown_decision.get(
            "verdict"
        )
    )

    print(
        "Reason  :",
        unknown_decision.get(
            "reason"
        )
    )

    print(
        "Rollback Status :",
        unknown_rollback_evidence.get(
            "rollback_status"
        )
    )

    print(
        "Rollback Detected :",
        unknown_rollback_evidence.get(
            "rollback_detected"
        )
    )

    print(
        "Journal Status :",
        unknown_journal_state.get(
            "journal_status"
        )
    )

    print(
        "Time Evidence Status :",
        unknown_time_evidence.get(
            "status"
        )
    )

    print(
        "Verification Latency :",
        unknown_latency_ms,
        "ms"
    )


    print(
        "\nInsufficient Evidence:"
    )

    for area in (
        unknown_decision.get(
            "insufficient_layers",
            []
        )
    ):

        print(
            "-",
            area
        )


    print(
        "\n--- STRUCTURED UNKNOWN REPORT ---"
    )

    print(
        "Scan ID :",
        unknown_report.get(
            "scan_id"
        )
    )

    print(
        "Verification Time :",
        unknown_report.get(
            "verification_time_utc"
        )
    )

    print(
        "Report Status : GENERATED"
    )

    print(
        "UNKNOWN Report Stored :",
        unknown_report_path
    )


# ==================================================
# MAIN WATCHER
# ==================================================

def main():

    argument_parser = (
        argparse.ArgumentParser(
            description=(
                "N3 NFC Integrity "
                "Verification System"
            )
        )
    )


    argument_parser.add_argument(
        "mode",
        help=(
            "Operation mode: "
            "ENROLL, VERIFY, or UPDATE"
        )
    )


    args = (
        argument_parser.parse_args()
    )


    mode = normalize_mode(
        args.mode
    )


    # --------------------------------------------------
    # CREATE REQUIRED DIRECTORIES
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


    print(
        "======================================"
    )

    print(
        "N3 AUTOMATIC FAMILY-AWARE SCAN WATCHER"
    )

    print(
        "======================================"
    )

    print(
        "N3 Mode :",
        mode
    )

    print(
        "\nSupported Families:"
    )

    print(
        "- NTAG215"
    )

    print(
        "- MIFARE Classic 1K"
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
    # WATCH LOOP
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


                # --------------------------------------------------
                # USB FAST PATH
                # --------------------------------------------------

                if file_path.name.startswith(
                    "N3_USB_SCAN_"
                ):

                    # Files produced by flipper_usb_adapter.py
                    # are first written as .tmp files and then
                    # atomically renamed to .nfc only after the
                    # complete NFC dump has been written.
                    #
                    # Therefore, when the watcher can see an
                    # N3_USB_SCAN_*.nfc file, it is already ready
                    # for immediate parsing.

                    print(
                        "USB Fast Path : READY"
                    )

                    file_ready = True


                # --------------------------------------------------
                # NORMAL FILE-READY CHECK
                # --------------------------------------------------

                else:

                    file_ready = (
                        wait_until_file_ready(
                            file_path
                        )
                    )


                # --------------------------------------------------
                # NOT READY
                # --------------------------------------------------

                if not file_ready:

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

                if quality_result.get(
                    "is_complete"
                ):

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
                            canonical_scan,
                            quality_result
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

                        handle_unknown_verification(
                            canonical_scan,
                            quality_result
                        )


                # --------------------------------------------------
                # ARCHIVE HANDLED ACQUISITION
                # --------------------------------------------------

                move_to_processed(
                    file_path
                )


                print(
                    "\nWaiting for NFC scans..."
                )


            # --------------------------------------------------
            # BASELINE ALREADY EXISTS
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


# ==================================================
# START PROGRAM
# ==================================================

if __name__ == "__main__":

    main()
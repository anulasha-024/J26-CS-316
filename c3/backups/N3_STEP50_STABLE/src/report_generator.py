from datetime import datetime, timezone
from pathlib import Path

import uuid
import json


# --------------------------------------------------
# N3 REPORT STORAGE PATH
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

REPORTS_DIR = PROJECT_ROOT / "reports"


# --------------------------------------------------
# N3 VERIFICATION REPORT GENERATOR
# --------------------------------------------------

def generate_verification_report(
    canonical_scan,
    baseline,
    raw_memory_result,
    ndef_result,
    security_result,
    final_decision,
    tamper_classes,
    journal_state=None,
):
    """
    Build one structured N3 verification report.

    Supports:

    NTAG215
        - page-based raw memory
        - NDEF application evidence
        - NTAG security state

    MIFARE Classic 1K
        - block/sector-based raw memory
        - controlled application-block evidence
        - sector-trailer security state
    """

    # --------------------------------------------------
    # UNIQUE SCAN ID
    # --------------------------------------------------

    scan_id = str(
        uuid.uuid4()
    )


    # --------------------------------------------------
    # VERIFICATION TIME
    # --------------------------------------------------

    verification_time_utc = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )


    # --------------------------------------------------
    # CARD INFORMATION
    # --------------------------------------------------

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

    memory_unit = card_info.get(
        "memory_unit"
    )


    # --------------------------------------------------
    # READER / ACQUISITION INFORMATION
    # --------------------------------------------------

    reader_metadata = canonical_scan.get(
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
    # BASELINE INFORMATION
    # --------------------------------------------------

    baseline_version = baseline.get(
        "baseline_version"
    )

    enrollment_time_utc = baseline.get(
        "enrollment_time_utc"
    )

    baseline_identity = baseline.get(
        "baseline_identity"
    )

    baseline_source_file = baseline.get(
        "source_file"
    )


    # --------------------------------------------------
    # JOURNAL STATE
    # --------------------------------------------------

    if journal_state is None:

        journal_state = {

            "journal_status":
                "NOT_EVALUATED",

            "reason":
                (
                    "Journal-state evaluation was "
                    "not supplied for this report."
                ),

            "latest_authorized_version":
                None,

            "baseline_version_used":
                baseline_version,
        }


    # --------------------------------------------------
    # BUILD REPORT
    # --------------------------------------------------

    report = {

        "scan_id":
            scan_id,

        "verification_time_utc":
            verification_time_utc,


        # --------------------------------------------------
        # CARD IDENTITY
        # --------------------------------------------------

        "card": {

            "card_family":
                card_family,

            "card_type":
                card_type,

            "uid":
                uid,

            "memory_unit":
                memory_unit,
        },


        # --------------------------------------------------
        # READER / ACQUISITION METADATA
        # --------------------------------------------------

        "reader_metadata": {

            "reader_name":
                reader_name,

            "acquisition_method":
                acquisition_method,

            "interface_type":
                interface_type,

            "source_file":
                source_file,
        },


        # --------------------------------------------------
        # TRUSTED BASELINE
        # --------------------------------------------------

        "baseline": {

            "baseline_identity":
                baseline_identity,

            "baseline_version":
                baseline_version,

            "enrollment_time_utc":
                enrollment_time_utc,

            "source_file":
                baseline_source_file,
        },


        # --------------------------------------------------
        # FINAL DECISION
        # --------------------------------------------------

        "final_decision": {

            "verdict":
                final_decision.get(
                    "verdict"
                ),

            "reason":
                final_decision.get(
                    "reason"
                ),

            "changed_layers":
                final_decision.get(
                    "changed_layers",
                    []
                ),

            "insufficient_layers":
                final_decision.get(
                    "insufficient_layers",
                    []
                ),

            "layer_statuses":
                final_decision.get(
                    "layer_statuses",
                    {}
                ),
        },


        # --------------------------------------------------
        # JOURNAL STATE
        # --------------------------------------------------

        "journal_state": {

            "journal_status":
                journal_state.get(
                    "journal_status"
                ),

            "reason":
                journal_state.get(
                    "reason"
                ),

            "latest_authorized_version":
                journal_state.get(
                    "latest_authorized_version"
                ),

            "baseline_version_used":
                journal_state.get(
                    "baseline_version_used"
                ),
        },


        # --------------------------------------------------
        # CHANGE / TAMPER CLASSIFICATION
        # --------------------------------------------------

        "tamper_classification":
            tamper_classes,


        # --------------------------------------------------
        # RAW MEMORY LAYER
        # --------------------------------------------------

        "raw_memory": {

            "card_family":
                raw_memory_result.get(
                    "card_family",
                    card_family
                ),

            "memory_unit":
                raw_memory_result.get(
                    "memory_unit",
                    memory_unit
                ),

            "status":
                raw_memory_result.get(
                    "status"
                ),


            # ----------------------------------------------
            # NTAG PAGE CHANGES
            # ----------------------------------------------

            "changed_page_count":
                raw_memory_result.get(
                    "changed_page_count",
                    0
                ),

            "changed_pages":
                raw_memory_result.get(
                    "changed_pages",
                    []
                ),


            # ----------------------------------------------
            # MIFARE BLOCK CHANGES
            # ----------------------------------------------

            "changed_block_count":
                raw_memory_result.get(
                    "changed_block_count",
                    0
                ),

            "changed_blocks":
                raw_memory_result.get(
                    "changed_blocks",
                    []
                ),

            "reason":
                raw_memory_result.get(
                    "reason"
                ),
        },


        # --------------------------------------------------
        # APPLICATION / NDEF LAYER
        # --------------------------------------------------

        "application_ndef": {

            "card_family":
                ndef_result.get(
                    "card_family",
                    card_family
                ),

            "application_type":
                ndef_result.get(
                    "application_type"
                ),

            "status":
                ndef_result.get(
                    "status"
                ),

            "changed_field_count":
                ndef_result.get(
                    "changed_field_count",
                    0
                ),

            "changed_fields":
                ndef_result.get(
                    "changed_fields",
                    []
                ),


            # MIFARE application evidence
            "baseline_marker":
                ndef_result.get(
                    "baseline_marker"
                ),

            "current_marker":
                ndef_result.get(
                    "current_marker"
                ),

            "reason":
                ndef_result.get(
                    "reason"
                ),
        },


        # --------------------------------------------------
        # SECURITY-STATE LAYER
        # --------------------------------------------------

        "security_state": {

            "card_family":
                security_result.get(
                    "card_family",
                    card_family
                ),

            "status":
                security_result.get(
                    "status"
                ),

            "changed_field_count":
                security_result.get(
                    "changed_field_count",
                    0
                ),

            "changed_fields":
                security_result.get(
                    "changed_fields",
                    []
                ),

            # MIFARE policy evidence
            "key_a_compared":
                security_result.get(
                    "key_a_compared"
                ),

            "key_b_compared":
                security_result.get(
                    "key_b_compared"
                ),

            "reason":
                security_result.get(
                    "reason"
                ),
        },
    }


    return report


# --------------------------------------------------
# GENERATE UNKNOWN VERIFICATION REPORT
# --------------------------------------------------

def generate_unknown_report(
    canonical_scan,
    quality_result,
    unknown_decision,
):
    """
    Build a structured N3 report when the current
    scan does not contain enough evidence.

    Supports page-based NTAG quality evidence and
    block-based MIFARE quality evidence.
    """

    # --------------------------------------------------
    # UNIQUE SCAN ID
    # --------------------------------------------------

    scan_id = str(
        uuid.uuid4()
    )


    # --------------------------------------------------
    # VERIFICATION TIME
    # --------------------------------------------------

    verification_time_utc = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )


    # --------------------------------------------------
    # CARD INFORMATION
    # --------------------------------------------------

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

    memory_unit = card_info.get(
        "memory_unit"
    )


    # --------------------------------------------------
    # READER / ACQUISITION INFORMATION
    # --------------------------------------------------

    reader_metadata = canonical_scan.get(
        "reader_metadata",
        {}
    )


    # --------------------------------------------------
    # BUILD UNKNOWN REPORT
    # --------------------------------------------------

    report = {

        "scan_id":
            scan_id,

        "verification_time_utc":
            verification_time_utc,


        # --------------------------------------------------
        # CARD
        # --------------------------------------------------

        "card": {

            "card_family":
                card_family,

            "card_type":
                card_type,

            "uid":
                uid,

            "memory_unit":
                memory_unit,
        },


        # --------------------------------------------------
        # READER / ACQUISITION METADATA
        # --------------------------------------------------

        "reader_metadata": {

            "reader_name":
                reader_metadata.get(
                    "reader_name"
                ),

            "acquisition_method":
                reader_metadata.get(
                    "acquisition_method"
                ),

            "interface_type":
                reader_metadata.get(
                    "interface_type"
                ),

            "source_file":
                reader_metadata.get(
                    "source_file"
                ),
        },


        # --------------------------------------------------
        # BASELINE
        # --------------------------------------------------

        "baseline": {

            "baseline_identity":
                None,

            "baseline_version":
                None,

            "enrollment_time_utc":
                None,

            "source_file":
                None,
        },


        # --------------------------------------------------
        # FINAL DECISION
        # --------------------------------------------------

        "final_decision": {

            "verdict":
                unknown_decision.get(
                    "verdict"
                ),

            "reason":
                unknown_decision.get(
                    "reason"
                ),

            "changed_layers":
                [],

            "insufficient_layers":
                unknown_decision.get(
                    "insufficient_layers",
                    []
                ),

            "layer_statuses":
                unknown_decision.get(
                    "layer_statuses",
                    {}
                ),
        },


        # --------------------------------------------------
        # JOURNAL STATE
        # --------------------------------------------------

        "journal_state": {

            "journal_status":
                "NOT_EVALUATED",

            "reason":
                (
                    "Journal-state verification was "
                    "not performed because the current "
                    "scan evidence was insufficient."
                ),

            "latest_authorized_version":
                None,

            "baseline_version_used":
                None,
        },


        # --------------------------------------------------
        # SCAN QUALITY
        # --------------------------------------------------

        "scan_quality": {

            "card_family":
                quality_result.get(
                    "card_family",
                    card_family
                ),

            "memory_unit":
                quality_result.get(
                    "memory_unit",
                    memory_unit
                ),

            "quality_status":
                quality_result.get(
                    "quality_status"
                ),

            "is_complete":
                quality_result.get(
                    "is_complete"
                ),


            # ----------------------------------------------
            # NTAG PAGE QUALITY
            # ----------------------------------------------

            "pages_total":
                quality_result.get(
                    "pages_total"
                ),

            "pages_read":
                quality_result.get(
                    "pages_read"
                ),

            "parsed_pages":
                quality_result.get(
                    "parsed_pages"
                ),

            "missing_pages":
                quality_result.get(
                    "missing_pages",
                    []
                ),


            # ----------------------------------------------
            # MIFARE BLOCK QUALITY
            # ----------------------------------------------

            "blocks_total":
                quality_result.get(
                    "blocks_total"
                ),

            "sectors_total":
                quality_result.get(
                    "sectors_total"
                ),

            "parsed_blocks":
                quality_result.get(
                    "parsed_blocks"
                ),

            "missing_blocks":
                quality_result.get(
                    "missing_blocks",
                    []
                ),

            "malformed_blocks":
                quality_result.get(
                    "malformed_blocks",
                    []
                ),


            # ----------------------------------------------
            # COMMON QUALITY EVIDENCE
            # ----------------------------------------------

            "unknown_byte_count":
                quality_result.get(
                    "unknown_byte_count"
                ),

            "reasons":
                quality_result.get(
                    "reasons",
                    []
                ),
        },


        # --------------------------------------------------
        # CHANGE CLASSIFICATION
        # --------------------------------------------------

        "tamper_classification":
            [],


        # --------------------------------------------------
        # RAW MEMORY
        # --------------------------------------------------

        "raw_memory": {

            "card_family":
                card_family,

            "memory_unit":
                memory_unit,

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
                    "Verification was not performed "
                    "because scan evidence was insufficient."
                ),
        },


        # --------------------------------------------------
        # APPLICATION / NDEF
        # --------------------------------------------------

        "application_ndef": {

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

            "baseline_marker":
                None,

            "current_marker":
                None,

            "reason":
                (
                    "Verification was not performed "
                    "because scan evidence was insufficient."
                ),
        },


        # --------------------------------------------------
        # SECURITY STATE
        # --------------------------------------------------

        "security_state": {

            "card_family":
                card_family,

            "status":
                "NOT_EVALUATED",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "key_a_compared":
                None,

            "key_b_compared":
                None,

            "reason":
                (
                    "Verification was not performed "
                    "because scan evidence was insufficient."
                ),
        },
    }


    return report


# --------------------------------------------------
# SAVE VERIFICATION REPORT
# --------------------------------------------------

def save_verification_report(
    report
):
    """
    Save one structured N3 verification report
    as a permanent JSON file.
    """

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    # --------------------------------------------------
    # GET SCAN ID
    # --------------------------------------------------

    scan_id = report.get(
        "scan_id"
    )

    if not scan_id:

        raise ValueError(
            "Verification report does not "
            "contain a scan ID."
        )


    # --------------------------------------------------
    # CREATE REPORT FILE NAME
    # --------------------------------------------------

    report_path = REPORTS_DIR / (
        f"N3_REPORT_{scan_id}.json"
    )


    # --------------------------------------------------
    # SAVE JSON
    # --------------------------------------------------

    with report_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )


    return report_path
from datetime import datetime, timezone
from pathlib import Path
import json


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

REPORTS_DIR = PROJECT_ROOT / "reports"


# --------------------------------------------------
# NORMALIZE UID
# --------------------------------------------------

def normalize_uid(uid):
    """
    Convert a UID into one consistent
    uppercase space-separated format.
    """

    if uid is None:
        return None

    return " ".join(
        str(uid).strip().upper().split()
    )


# --------------------------------------------------
# NORMALIZE CARD TYPE
# --------------------------------------------------

def normalize_card_type(card_type):
    """
    Convert card type into one consistent format.
    """

    if card_type is None:
        return None

    return str(
        card_type
    ).strip().upper()


# --------------------------------------------------
# PARSE ISO TIMESTAMP
# --------------------------------------------------

def parse_iso_time(value):
    """
    Convert an ISO-8601 timestamp string
    into a timezone-aware Python datetime.
    """

    if not value:
        return None

    try:

        normalized_value = str(
            value
        ).strip()

        if normalized_value.endswith(
            "Z"
        ):

            normalized_value = (
                normalized_value[:-1]
                + "+00:00"
            )

        parsed_time = datetime.fromisoformat(
            normalized_value
        )

        # If a timestamp has no timezone,
        # treat it as UTC for consistency.
        if parsed_time.tzinfo is None:

            parsed_time = parsed_time.replace(
                tzinfo=timezone.utc
            )

        return parsed_time

    except (
        TypeError,
        ValueError
    ):

        return None


# --------------------------------------------------
# LOAD PREVIOUS REPORT HISTORY
# --------------------------------------------------

def load_report_history(
    card_type,
    uid,
    current_verification_time_utc=None,
    exclude_scan_id=None,
):
    """
    Load previous N3 verification reports
    belonging to the same NFC tag.
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

    current_time = parse_iso_time(
        current_verification_time_utc
    )

    history = []

    if not REPORTS_DIR.exists():

        return history


    for report_path in REPORTS_DIR.glob(
        "N3_REPORT_*.json"
    ):

        try:

            report = json.loads(
                report_path.read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            json.JSONDecodeError
        ):

            continue


        # --------------------------------------------------
        # SKIP CURRENT SCAN IF REQUIRED
        # --------------------------------------------------

        scan_id = report.get(
            "scan_id"
        )

        if (
            exclude_scan_id
            and scan_id == exclude_scan_id
        ):

            continue


        # --------------------------------------------------
        # CHECK CARD IDENTITY
        # --------------------------------------------------

        card = report.get(
            "card",
            {}
        )

        report_card_type = (
            normalize_card_type(
                card.get(
                    "card_type"
                )
            )
        )

        report_uid = normalize_uid(
            card.get(
                "uid"
            )
        )

        if (
            report_card_type
            != normalized_card_type
        ):

            continue

        if report_uid != normalized_uid:

            continue


        # --------------------------------------------------
        # READ VERIFICATION TIME
        # --------------------------------------------------

        verification_time_utc = (
            report.get(
                "verification_time_utc"
            )
        )

        verification_time = (
            parse_iso_time(
                verification_time_utc
            )
        )

        if verification_time is None:

            continue


        # --------------------------------------------------
        # DO NOT USE CURRENT/FUTURE REPORTS
        # --------------------------------------------------

        if (
            current_time is not None
            and verification_time
            >= current_time
        ):

            continue


        # --------------------------------------------------
        # READ VERDICT
        # --------------------------------------------------

        final_decision = report.get(
            "final_decision",
            {}
        )

        verdict = final_decision.get(
            "verdict"
        )

        if verdict:

            verdict = str(
                verdict
            ).strip().upper()


        history.append(
            {
                "scan_id":
                    scan_id,

                "verification_time_utc":
                    verification_time_utc,

                "verification_time":
                    verification_time,

                "verdict":
                    verdict,

                "source":
                    "VERIFICATION_REPORT",

                "baseline_version":
                    report.get(
                        "baseline",
                        {}
                    ).get(
                        "baseline_version"
                    ),

                "report_path":
                    str(
                        report_path
                    ),
            }
        )


    history.sort(
        key=lambda item:
            item[
                "verification_time"
            ]
    )

    return history


# --------------------------------------------------
# FIND LAST VALID VERIFICATION REPORT
# --------------------------------------------------

def find_last_valid_report(
    history
):
    """
    Return the most recent previous VALID
    verification report for this NFC tag.
    """

    valid_events = [
        event
        for event in history
        if event.get(
            "verdict"
        ) == "VALID"
    ]

    if not valid_events:

        return None

    return valid_events[-1]


# --------------------------------------------------
# BUILD TRUSTED BASELINE REFERENCE EVENT
# --------------------------------------------------

def build_trusted_baseline_event(
    trusted_baseline_time_utc,
    trusted_baseline_version=None,
    current_verification_time_utc=None,
):
    """
    Convert a trusted baseline creation/enrollment
    time into a known-valid reference event.

    The baseline should already have been loaded
    and HMAC-verified by the normal N3 workflow.
    """

    baseline_time = parse_iso_time(
        trusted_baseline_time_utc
    )

    if baseline_time is None:

        return None

    current_time = parse_iso_time(
        current_verification_time_utc
    )

    # Do not use a baseline timestamp that appears
    # to be later than the current verification.
    if (
        current_time is not None
        and baseline_time > current_time
    ):

        return None

    return {
        "scan_id":
            None,

        "verification_time_utc":
            trusted_baseline_time_utc,

        "verification_time":
            baseline_time,

        "verdict":
            "VALID",

        "source":
            "TRUSTED_BASELINE",

        "baseline_version":
            trusted_baseline_version,

        "report_path":
            None,
    }


# --------------------------------------------------
# SELECT LAST KNOWN VALID EVIDENCE
# --------------------------------------------------

def find_last_known_valid(
    history,
    trusted_baseline_time_utc=None,
    trusted_baseline_version=None,
    current_verification_time_utc=None,
):
    """
    Select the latest trustworthy known-valid
    observation.

    Sources can be:
    - a previous VALID verification report
    - the trusted baseline creation/enrollment time
    """

    candidates = []


    # --------------------------------------------------
    # CANDIDATE 1: PREVIOUS VALID REPORT
    # --------------------------------------------------

    valid_report = find_last_valid_report(
        history
    )

    if valid_report:

        candidates.append(
            valid_report
        )


    # --------------------------------------------------
    # CANDIDATE 2: TRUSTED BASELINE
    # --------------------------------------------------

    baseline_event = (
        build_trusted_baseline_event(
            trusted_baseline_time_utc=(
                trusted_baseline_time_utc
            ),
            trusted_baseline_version=(
                trusted_baseline_version
            ),
            current_verification_time_utc=(
                current_verification_time_utc
            ),
        )
    )

    if baseline_event:

        candidates.append(
            baseline_event
        )


    # --------------------------------------------------
    # NO KNOWN VALID EVIDENCE
    # --------------------------------------------------

    if not candidates:

        return None


    # --------------------------------------------------
    # USE MOST RECENT TRUSTED VALID EVIDENCE
    # --------------------------------------------------

    candidates.sort(
        key=lambda item:
            item[
                "verification_time"
            ]
    )

    return candidates[-1]


# --------------------------------------------------
# FIND FIRST DETECTED MODIFIED
# --------------------------------------------------

def find_first_detected_modified(
    history,
    last_known_valid_event=None,
    current_verdict=None,
    current_verification_time_utc=None,
    current_scan_id=None,
):
    """
    Find the earliest MODIFIED observation
    after the last known valid observation.

    The current verification can also act as
    the first detected MODIFIED event.
    """

    last_valid_time = None

    if last_known_valid_event:

        last_valid_time = (
            last_known_valid_event.get(
                "verification_time"
            )
        )


    modified_events = []

    for event in history:

        if event.get(
            "verdict"
        ) != "MODIFIED":

            continue

        event_time = event.get(
            "verification_time"
        )

        if event_time is None:

            continue

        if (
            last_valid_time is not None
            and event_time
            <= last_valid_time
        ):

            continue

        modified_events.append(
            event
        )


    # --------------------------------------------------
    # INCLUDE CURRENT MODIFIED OBSERVATION
    # --------------------------------------------------

    if (
        str(
            current_verdict
        ).strip().upper()
        == "MODIFIED"
    ):

        current_time = parse_iso_time(
            current_verification_time_utc
        )

        if current_time is not None:

            modified_events.append(
                {
                    "scan_id":
                        current_scan_id,

                    "verification_time_utc":
                        current_verification_time_utc,

                    "verification_time":
                        current_time,

                    "verdict":
                        "MODIFIED",

                    "source":
                        "CURRENT_VERIFICATION",

                    "baseline_version":
                        None,

                    "report_path":
                        None,
                }
            )


    if not modified_events:

        return None


    modified_events.sort(
        key=lambda item:
            item[
                "verification_time"
            ]
    )

    return modified_events[0]


# --------------------------------------------------
# BUILD TIME EVIDENCE
# --------------------------------------------------

def build_time_evidence(
    card_type,
    uid,
    current_verdict,
    current_verification_time_utc,
    current_scan_id=None,
    trusted_baseline_time_utc=None,
    trusted_baseline_version=None,
):
    """
    Build conservative N3 time evidence.

    This function does NOT claim the exact
    external modification time.

    It records:
    - last known valid observation
    - first detected modified observation
    - possible modification window

    A trusted baseline creation/enrollment time
    can be used as known-valid evidence when
    appropriate.
    """

    verdict = str(
        current_verdict
    ).strip().upper()


    # --------------------------------------------------
    # LOAD PREVIOUS VERIFICATION HISTORY
    # --------------------------------------------------

    history = load_report_history(
        card_type=card_type,
        uid=uid,
        current_verification_time_utc=(
            current_verification_time_utc
        ),
        exclude_scan_id=current_scan_id,
    )


    # --------------------------------------------------
    # FIND BEST LAST-KNOWN-VALID EVIDENCE
    # --------------------------------------------------

    last_known_valid = (
        find_last_known_valid(
            history=history,

            trusted_baseline_time_utc=(
                trusted_baseline_time_utc
            ),

            trusted_baseline_version=(
                trusted_baseline_version
            ),

            current_verification_time_utc=(
                current_verification_time_utc
            ),
        )
    )


    # --------------------------------------------------
    # CURRENT STATE IS VALID
    # --------------------------------------------------

    if verdict == "VALID":

        return {

            "status":
                "CURRENT_STATE_VALID",

            "last_known_valid_utc":
                current_verification_time_utc,

            "last_known_valid_source":
                "CURRENT_VERIFICATION",

            "last_known_valid_baseline_version":
                trusted_baseline_version,

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
                    "The current NFC state is VALID, "
                    "so the current verification time "
                    "becomes the latest known-valid "
                    "observation."
                ),
        }


    # --------------------------------------------------
    # CURRENT STATE IS MODIFIED
    # --------------------------------------------------

    if verdict == "MODIFIED":

        first_detected_modified = (
            find_first_detected_modified(
                history=history,

                last_known_valid_event=(
                    last_known_valid
                ),

                current_verdict=verdict,

                current_verification_time_utc=(
                    current_verification_time_utc
                ),

                current_scan_id=(
                    current_scan_id
                ),
            )
        )


        # --------------------------------------------------
        # LAST KNOWN VALID DETAILS
        # --------------------------------------------------

        last_known_valid_time = None
        last_known_valid_source = None
        last_known_valid_version = None

        if last_known_valid:

            last_known_valid_time = (
                last_known_valid.get(
                    "verification_time_utc"
                )
            )

            last_known_valid_source = (
                last_known_valid.get(
                    "source"
                )
            )

            last_known_valid_version = (
                last_known_valid.get(
                    "baseline_version"
                )
            )


        # --------------------------------------------------
        # FIRST MODIFIED DETAILS
        # --------------------------------------------------

        first_modified_time = None

        if first_detected_modified:

            first_modified_time = (
                first_detected_modified.get(
                    "verification_time_utc"
                )
            )


        # --------------------------------------------------
        # FULL MODIFICATION WINDOW AVAILABLE
        # --------------------------------------------------

        if (
            last_known_valid_time
            and first_modified_time
        ):

            return {

                "status":
                    "MODIFICATION_WINDOW_AVAILABLE",

                "last_known_valid_utc":
                    last_known_valid_time,

                "last_known_valid_source":
                    last_known_valid_source,

                "last_known_valid_baseline_version":
                    last_known_valid_version,

                "first_detected_modified_utc":
                    first_modified_time,

                "possible_modification_window": {

                    "start_utc":
                        last_known_valid_time,

                    "end_utc":
                        first_modified_time,
                },

                "exact_modification_time_utc":
                    None,

                "reason":
                    (
                        "The exact external modification "
                        "time is unknown. The change could "
                        "have occurred after the last known "
                        "valid observation and before the "
                        "first MODIFIED detection."
                    ),
            }


        # --------------------------------------------------
        # NO PRIOR KNOWN-VALID EVIDENCE
        # --------------------------------------------------

        return {

            "status":
                "NO_PRIOR_VALID_OBSERVATION",

            "last_known_valid_utc":
                None,

            "last_known_valid_source":
                None,

            "last_known_valid_baseline_version":
                None,

            "first_detected_modified_utc":
                first_modified_time,

            "possible_modification_window": {

                "start_utc":
                    None,

                "end_utc":
                    first_modified_time,
            },

            "exact_modification_time_utc":
                None,

            "reason":
                (
                    "A MODIFIED state was detected, but "
                    "no trusted earlier known-valid "
                    "observation is available to establish "
                    "the beginning of a modification window."
                ),
        }


    # --------------------------------------------------
    # CURRENT STATE IS UNKNOWN
    # --------------------------------------------------

    if verdict == "UNKNOWN":

        last_known_valid_time = None
        last_known_valid_source = None
        last_known_valid_version = None

        if last_known_valid:

            last_known_valid_time = (
                last_known_valid.get(
                    "verification_time_utc"
                )
            )

            last_known_valid_source = (
                last_known_valid.get(
                    "source"
                )
            )

            last_known_valid_version = (
                last_known_valid.get(
                    "baseline_version"
                )
            )

        return {

            "status":
                "INSUFFICIENT_EVIDENCE",

            "last_known_valid_utc":
                last_known_valid_time,

            "last_known_valid_source":
                last_known_valid_source,

            "last_known_valid_baseline_version":
                last_known_valid_version,

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
                    "The current scan is UNKNOWN, so N3 "
                    "does not infer that a modification "
                    "occurred and does not create a "
                    "modification-time window."
                ),
        }


    # --------------------------------------------------
    # UNSUPPORTED VERDICT
    # --------------------------------------------------

    return {

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
                "Time evidence could not be evaluated "
                "because the verification verdict was "
                "not recognized."
            ),
    }


# --------------------------------------------------
# SIMPLE MODULE TEST
# --------------------------------------------------

if __name__ == "__main__":

    print(
        "time_evidence.py loaded successfully."
    )
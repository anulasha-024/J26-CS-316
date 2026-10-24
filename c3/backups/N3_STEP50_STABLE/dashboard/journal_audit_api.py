"""Read-only, report-derived Journal & Audit endpoints for N3_TIVE.

These endpoints DO NOT modify trusted baselines or the journal database.
They summarize saved N3_REPORT_*.json files. They are not a substitute
for a database-level journal or a cryptographically tamper-evident audit log.
"""

from collections import Counter
from pathlib import Path
import json
import re
import uuid

from flask import Blueprint, jsonify, request


journal_audit_bp = Blueprint("n3_journal_audit", __name__)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORT_GLOB = "N3_REPORT_*.json"
MAX_SCAN_FILES = 10000  # hard cap to avoid unbounded dashboard reads


def dictionary(value):
    return value if isinstance(value, dict) else {}


def first_value(obj, *keys):
    """Return first available value without fabricating missing evidence."""
    for key in keys:
        value = obj.get(key)
        if value is not None and value != "":
            return value
    return None


def report_files():
    if not REPORTS_DIR.is_dir():
        return []
    paths = [p for p in REPORTS_DIR.glob(REPORT_GLOB) if p.is_file()]
    paths.sort(key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    return paths[:MAX_SCAN_FILES]


def summary_for(report):
    card = dictionary(report.get("card"))
    decision = dictionary(report.get("final_decision"))
    journal = dictionary(report.get("journal_state"))
    rollback = dictionary(report.get("rollback_evidence"))
    baseline = dictionary(report.get("baseline"))
    time_info = dictionary(report.get("time_evidence"))
    metrics = dictionary(report.get("performance_metrics"))

    verdict = first_value(decision, "verdict") or "UNKNOWN"
    journal_status = first_value(journal, "journal_status") or "NOT_EVALUATED"
    rollback_detected = first_value(rollback, "rollback_detected")

    return {
        "scan_id": report.get("scan_id"),
        "verification_time_utc": report.get("verification_time_utc"),
        "card_family": card.get("card_family") or card.get("card_type"),
        "uid": card.get("uid"),
        "verdict": verdict,
        "journal_status": journal_status,
        "rollback_detected": rollback_detected,
        "active_baseline_version": first_value(rollback, "active_baseline_version"),
        "baseline_version_used": first_value(baseline, "baseline_version"),
        "latest_authorized_version": first_value(journal, "latest_authorized_version"),
        "time_evidence_status": first_value(time_info, "status"),
        "latency_ms": first_value(metrics, "verification_latency_ms"),
    }


def detail_for(report):
    summary = summary_for(report)
    decision = dictionary(report.get("final_decision"))
    journal = dictionary(report.get("journal_state"))
    rollback = dictionary(report.get("rollback_evidence"))
    time_info = dictionary(report.get("time_evidence"))
    raw = dictionary(report.get("raw_memory"))
    application = dictionary(report.get("application_ndef"))
    security = dictionary(report.get("security_state"))

    # Deliberately omit card raw bytes, NDEF payload, keys, HMAC,
    # and the entire stored report from this audit API.
    layers = dictionary(decision.get("layer_statuses"))
    changes = []
    for item in raw.get("changed_pages") or []:
        if isinstance(item, dict):
            changes.append({
                "unit": "PAGE",
                "number": item.get("page"),
                "sector": None,
                "region": item.get("region"),
            })
    for item in raw.get("changed_blocks") or []:
        if isinstance(item, dict):
            changes.append({
                "unit": "BLOCK",
                "number": item.get("block_number", item.get("block")),
                "sector": item.get("sector_number", item.get("sector")),
                "region": item.get("region"),
            })

    summary.update({
        "decision_reason": decision.get("reason"),
        "journal_reason": journal.get("reason"),
        "rollback_status": rollback.get("status") or rollback.get("rollback_status"),
        "matched_older_version": first_value(rollback, "matched_older_version"),
        "changed_layers": decision.get("changed_layers") or [],
        "tamper_classification": report.get("tamper_classification") or [],
        "application_status": application.get("status") or layers.get("APPLICATION_NDEF"),
        "raw_memory_status": raw.get("status") or layers.get("RAW_MEMORY"),
        "security_status": security.get("status") or layers.get("SECURITY_STATE"),
        "changed_locations": changes[:150],
        "time_evidence": {
            "status": time_info.get("status"),
            "last_known_valid_utc": first_value(
                time_info, "last_known_valid_utc", "last_known_valid"
            ),
            "first_detected_modified_utc": first_value(
                time_info, "first_detected_modified_utc", "first_detected_modified"
            ),
            "possible_window_start_utc": first_value(
                time_info, "possible_window_start_utc", "possible_window_start"
            ),
            "possible_window_end_utc": first_value(
                time_info, "possible_window_end_utc", "possible_window_end"
            ),
            "exact_modification_time_utc": first_value(
                time_info, "exact_modification_time_utc", "exact_modification_time"
            ),
            "reason": time_info.get("reason"),
        },
    })
    return summary


def get_positive_query_int(key, default, low, high):
    raw = request.args.get(key, str(default))
    try:
        parsed = int(raw)
    except (ValueError, TypeError):
        return None
    return parsed if low <= parsed <= high else None


def load_reports():
    records = []
    skipped = 0
    for path in report_files():
        try:
            with path.open("r", encoding="utf-8") as handle:
                record = json.load(handle)
            if not isinstance(record, dict):
                raise ValueError("Expected object")
            records.append(summary_for(record))
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            skipped += 1
    return records, skipped


@journal_audit_bp.get("/api/journal-audit")
def api_journal_audit():
    """Paginated journal/verification evidence derived from saved reports."""
    limit = get_positive_query_int("limit", 25, 1, 100)
    offset = get_positive_query_int("offset", 0, 0, 100000)
    if limit is None or offset is None:
        return jsonify({"status": "ERROR", "message": "Invalid limit or offset."}), 400

    status = request.args.get("status", "").strip().upper()
    search = request.args.get("q", "").strip().upper()
    if len(status) > 64 or len(search) > 96:
        return jsonify({"status": "ERROR", "message": "Filter too long."}), 400
    if status and not re.fullmatch(r"[A-Z0-9_\-]+", status):
        return jsonify({"status": "ERROR", "message": "Invalid journal status."}), 400

    records, skipped = load_reports()
    counts = Counter(r["journal_status"] for r in records)
    verdict_counts = Counter(r["verdict"] for r in records)
    # Use a straightforward two-stage filter for clarity.
    matches = [r for r in records if not status or r["journal_status"].upper() == status]
    if search:
        matches = [
            r for r in matches
            if search in str(r["uid"] or "").upper()
            or search in str(r["card_family"] or "").upper()
        ]

    return jsonify({
        "status": "OK",
        "source": "VERIFICATION_REPORTS",
        "read_only": True,
        "total": len(matches),
        "all_report_count": len(records),
        "skipped_invalid_reports": skipped,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < len(matches),
        "journal_status_counts": dict(counts),
        "verdict_counts": dict(verdict_counts),
        "events": matches[offset:offset + limit],
    })


@journal_audit_bp.get("/api/journal-audit/<scan_id>")
def api_journal_audit_detail(scan_id):
    try:
        parsed = str(uuid.UUID(scan_id))
    except (ValueError, AttributeError):
        return jsonify({"status": "ERROR", "message": "Invalid scan ID."}), 404

    path = REPORTS_DIR / f"N3_REPORT_{parsed}.json"
    if not path.is_file():
        return jsonify({"status": "ERROR", "message": "Report not found."}), 404
    try:
        with path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
        if not isinstance(report, dict) or report.get("scan_id") != parsed:
            raise ValueError("Scan ID mismatch or invalid report")
        return jsonify({"status": "OK", "event": detail_for(report)})
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return jsonify({"status": "ERROR", "message": "Could not read this report."}), 500


from pathlib import Path
import json
import logging
import uuid

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    abort,
)


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

REPORTS_DIR = (
    PROJECT_ROOT
    / "reports"
)

DATABASE_PATH = (
    PROJECT_ROOT
    / "database"
    / "n3_integrity.db"
)

RUNTIME_STATE_PATH = (
    PROJECT_ROOT
    / "data"
    / "n3_runtime_state.json"
)


# --------------------------------------------------
# FLASK APPLICATION
# --------------------------------------------------

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

# Suppress repeated HTTP polling lines in the terminal.
logging.getLogger("werkzeug").setLevel(logging.ERROR)


# --------------------------------------------------
# REPORT FILE DISCOVERY
# --------------------------------------------------

def get_report_paths():
    """Return report files, newest first."""

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    files = list(REPORTS_DIR.glob("N3_REPORT_*.json"))

    # File timestamps are already used for /api/latest.
    # Use the same order for a consistent history view.
    return sorted(
        files,
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def get_latest_report_path():
    files = get_report_paths()
    return files[0] if files else None


# --------------------------------------------------
# READ JSON REPORT
# --------------------------------------------------

def read_report_file(report_path):
    with report_path.open("r", encoding="utf-8") as file:
        report_data = json.load(file)

    if not isinstance(report_data, dict):
        raise ValueError("Report JSON must contain an object.")

    return report_data


def load_latest_report():
    report_path = get_latest_report_path()

    if report_path is None:
        return {
            "status": "NO_REPORT",
            "message": "No N3 verification report is currently available.",
            "_dashboard_metadata": {"report_file": None},
        }

    try:
        report_data = read_report_file(report_path)

    except (OSError, json.JSONDecodeError, ValueError) as error:
        return {
            "status": "ERROR",
            "message": "The latest N3 report could not be loaded.",
            "error": str(error),
            "_dashboard_metadata": {
                "report_file": report_path.name,
            },
        }

    report_data["_dashboard_metadata"] = {
        "report_file": report_path.name,
    }

    return report_data


# --------------------------------------------------
# LIVE RUNTIME STATE
# --------------------------------------------------

def load_runtime_state():
    if not RUNTIME_STATE_PATH.exists():
        return {
            "status": "STARTING",
            "message": "Waiting for the NFC acquisition service.",
            "updated_at_utc": None,
        }

    try:
        with RUNTIME_STATE_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        return {
            "status": "ERROR",
            "message": "Runtime state could not be loaded.",
            "error": str(error),
        }


# --------------------------------------------------
# SCAN HISTORY SUMMARY
# --------------------------------------------------

def summarize_report(report_data, report_path):
    """Return the non-sensitive fields needed for a history table."""

    card = report_data.get("card") or {}
    if not isinstance(card, dict):
        card = {}

    decision = report_data.get("final_decision") or {}
    if not isinstance(decision, dict):
        decision = {}

    baseline = report_data.get("baseline") or {}
    if not isinstance(baseline, dict):
        baseline = {}

    metrics = report_data.get("performance_metrics") or {}
    if not isinstance(metrics, dict):
        metrics = {}

    reader = report_data.get("reader_metadata") or {}
    if not isinstance(reader, dict):
        reader = {}

    return {
        "scan_id": report_data.get("scan_id"),
        "verification_time_utc": report_data.get("verification_time_utc"),
        "card_family": card.get("card_family") or card.get("card_type"),
        "card_type": card.get("card_type"),
        "uid": card.get("uid"),
        "verdict": decision.get("verdict") or "UNKNOWN",
        "changed_layers": decision.get("changed_layers") or [],
        "baseline_version": baseline.get("baseline_version"),
        "verification_latency_ms": metrics.get("verification_latency_ms"),
        "source_file": reader.get("source_file"),
        "report_file": report_path.name,
    }


def read_bounded_int(name, default, minimum, maximum):
    """Validate paging parameters without allowing unbounded reads."""

    raw_value = request.args.get(name, str(default))

    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        abort(400, description=f"'{name}' must be an integer.")

    if not minimum <= value <= maximum:
        abort(
            400,
            description=f"'{name}' must be between {minimum} and {maximum}.",
        )

    return value


# --------------------------------------------------
# HTTP ROUTES
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/latest")
def api_latest():
    return jsonify(load_latest_report())


@app.route("/api/runtime")
def api_runtime():
    return jsonify(load_runtime_state())


@app.route("/api/history")
def api_history():
    """Return most recent verification reports for the Scan History UI."""

    limit = read_bounded_int("limit", 50, 1, 100)
    offset = read_bounded_int("offset", 0, 0, 1000000)

    paths = get_report_paths()
    selected = paths[offset: offset + limit]
    rows = []
    skipped = 0

    for path in selected:
        try:
            rows.append(
                summarize_report(read_report_file(path), path)
            )
        except (OSError, json.JSONDecodeError, ValueError):
            # One damaged report must not crash the whole history list.
            skipped += 1

    return jsonify({
        "status": "OK",
        "total": len(paths),
        "offset": offset,
        "limit": limit,
        "count": len(rows),
        "skipped_invalid_reports": skipped,
        "has_more": offset + limit < len(paths),
        "history": rows,
    })


@app.route("/api/history/<scan_id>")
def api_history_detail(scan_id):
    """Retrieve a specific complete report by its UUID scan ID."""

    try:
        canonical_id = str(uuid.UUID(scan_id))
    except (ValueError, AttributeError):
        abort(404)

    report_path = REPORTS_DIR / f"N3_REPORT_{canonical_id}.json"

    if not report_path.is_file():
        abort(404)

    try:
        data = read_report_file(report_path)
    except (OSError, json.JSONDecodeError, ValueError):
        return jsonify({
            "status": "ERROR",
            "message": "The selected report cannot be loaded.",
        }), 500

    data["_dashboard_metadata"] = {
        "report_file": report_path.name,
    }
    return jsonify(data)


@app.route("/api/health")
def api_health():
    latest_report = get_latest_report_path()

    return jsonify({
        "status": "ONLINE",
        "dashboard": "N3_TIVE",
        "reports_directory": str(REPORTS_DIR),
        "database_path": str(DATABASE_PATH),
        "runtime_state": str(RUNTIME_STATE_PATH),
        "latest_report": (
            latest_report.name if latest_report else None
        ),
    })


# --------------------------------------------------
# START DASHBOARD
# --------------------------------------------------

if __name__ == "__main__":
    print("\n========================================")
    print("N3 DASHBOARD")
    print("========================================")
    print("Dashboard      : http://127.0.0.1:5000")
    print("Latest Report  : http://127.0.0.1:5000/api/latest")
    print("Runtime State  : http://127.0.0.1:5000/api/runtime")
    print("Scan History   : http://127.0.0.1:5000/api/history")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True,
    )

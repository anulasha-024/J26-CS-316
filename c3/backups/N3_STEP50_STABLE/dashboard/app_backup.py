from pathlib import Path
import json
import logging

from flask import (
    Flask,
    jsonify,
    render_template,
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


# Reduce noisy polling logs during viva/demo.
logging.getLogger(
    "werkzeug"
).setLevel(
    logging.ERROR
)


# --------------------------------------------------
# GET LATEST N3 REPORT FILE
# --------------------------------------------------

def get_latest_report_path():

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_files = list(
        REPORTS_DIR.glob(
            "N3_REPORT_*.json"
        )
    )

    if not report_files:
        return None

    return max(
        report_files,
        key=lambda path:
            path.stat().st_mtime
    )


# --------------------------------------------------
# LOAD LATEST N3 REPORT
# --------------------------------------------------

def load_latest_report():

    report_path = (
        get_latest_report_path()
    )

    if report_path is None:

        return {
            "status":
                "NO_REPORT",

            "message":
                (
                    "No N3 verification report "
                    "is currently available."
                ),

            "_dashboard_metadata": {
                "report_file":
                    None,
            },
        }


    try:

        with report_path.open(
            "r",
            encoding="utf-8"
        ) as file:

            report_data = (
                json.load(
                    file
                )
            )

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:

        return {
            "status":
                "ERROR",

            "message":
                (
                    "The latest N3 report "
                    "could not be loaded."
                ),

            "error":
                str(
                    error
                ),

            "_dashboard_metadata": {
                "report_file":
                    report_path.name,
            },
        }


    report_data[
        "_dashboard_metadata"
    ] = {
        "report_file":
            report_path.name,
    }

    return report_data


# --------------------------------------------------
# LOAD LIVE RUNTIME STATE
# --------------------------------------------------

def load_runtime_state():

    if not RUNTIME_STATE_PATH.exists():

        return {
            "status":
                "STARTING",

            "message":
                (
                    "Waiting for the NFC "
                    "acquisition service."
                ),

            "updated_at_utc":
                None,
        }


    try:

        with RUNTIME_STATE_PATH.open(
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(
                file
            )

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:

        return {
            "status":
                "ERROR",

            "message":
                (
                    "Runtime state could "
                    "not be loaded."
                ),

            "error":
                str(
                    error
                ),
        }


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# --------------------------------------------------
# LATEST REPORT API
# --------------------------------------------------

@app.route("/api/latest")
def api_latest():

    return jsonify(
        load_latest_report()
    )


# --------------------------------------------------
# LIVE RUNTIME API
# --------------------------------------------------

@app.route("/api/runtime")
def api_runtime():

    return jsonify(
        load_runtime_state()
    )


# --------------------------------------------------
# HEALTH API
# --------------------------------------------------

@app.route("/api/health")
def api_health():

    latest_report = (
        get_latest_report_path()
    )

    return jsonify(
        {
            "status":
                "ONLINE",

            "dashboard":
                "N3_TIVE",

            "reports_directory":
                str(
                    REPORTS_DIR
                ),

            "database_path":
                str(
                    DATABASE_PATH
                ),

            "runtime_state":
                str(
                    RUNTIME_STATE_PATH
                ),

            "latest_report":
                (
                    latest_report.name
                    if latest_report
                    else None
                ),
        }
    )


# --------------------------------------------------
# START DASHBOARD
# --------------------------------------------------

if __name__ == "__main__":

    print()

    print(
        "========================================"
    )

    print(
        "N3 DASHBOARD"
    )

    print(
        "========================================"
    )

    print(
        "Dashboard:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print()

    print(
        "Latest Report API:"
    )

    print(
        "http://127.0.0.1:5000/api/latest"
    )

    print()

    print(
        "Runtime API:"
    )

    print(
        "http://127.0.0.1:5000/api/runtime"
    )

    print()


    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
"""One-time, idempotent installer for the read-only N3 baseline dashboard.
Run from project root: python install_baseline_management.py
Does not alter verification, enrollment, secrets, or baseline data.
"""

from datetime import datetime
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard"
APP_PATH = DASHBOARD / "app.py"
INDEX_PATH = DASHBOARD / "templates" / "index.html"
API_PATH = DASHBOARD / "baseline_api.py"
JS_PATH = DASHBOARD / "static" / "js" / "baseline.js"
HISTORY_JS_PATH = DASHBOARD / "static" / "js" / "history.js"

APP_BEGIN = "# === N3 BASELINE MANAGEMENT ADDON (READ ONLY) ==="
APP_END = "# === END N3 BASELINE MANAGEMENT ADDON ==="
APP_PATCH = f'''{APP_BEGIN}
# Initialize isolated baseline GET API without modifying core N3 logic.
import sys as _n3_baseline_sys
_n3_baseline_dashboard = str(Path(__file__).resolve().parent)
if _n3_baseline_dashboard not in _n3_baseline_sys.path:
    _n3_baseline_sys.path.insert(0, _n3_baseline_dashboard)
from baseline_api import register_baseline_routes
register_baseline_routes(app)
{APP_END}


'''
SCRIPT_MARKER = "filename='js/baseline.js'"
SCRIPT_PATCH = '''
<!-- N3 Baseline Management — read only -->
<script src="{{ url_for('static', filename='js/baseline.js') }}"></script>
'''


def main():
    for path in [APP_PATH, INDEX_PATH, API_PATH, JS_PATH, HISTORY_JS_PATH]:
        if not path.is_file():
            print(f"ERROR: Required file missing: {path}")
            return 1

    app_source = APP_PATH.read_text(encoding="utf-8")
    index_source = INDEX_PATH.read_text(encoding="utf-8")

    if "@app.route(\"/api/history\")" not in app_source and \
            "@app.get(\"/api/history\")" not in app_source:
        print("ERROR: /api/history route missing from app.py. Keep the working Scan History backend before installing.")
        return 1
    if "filename='js/history.js'" not in index_source:
        print("ERROR: history.js script reference was not found in index.html.")
        return 1
    if "if __name__ == \"__main__\":" not in app_source and APP_BEGIN not in app_source:
        print("ERROR: Cannot locate app.py startup section for safe patch.")
        return 1
    if "</body>" not in index_source.lower() and SCRIPT_MARKER not in index_source:
        print("ERROR: Cannot locate HTML closing body tag for safe patch.")
        return 1

    app_updated = app_source
    html_updated = index_source

    if APP_BEGIN not in app_source:
        app_updated = app_source.replace(
            'if __name__ == "__main__":',
            APP_PATCH + 'if __name__ == "__main__":',
            1,
        )

    if SCRIPT_MARKER not in index_source:
        pos = index_source.lower().rfind("</body>")
        html_updated = index_source[:pos] + SCRIPT_PATCH + "\n" + index_source[pos:]

    # Syntax check on the final code BEFORE overwriting the user's file.
    try:
        compile(app_updated, str(APP_PATH), "exec")
    except SyntaxError as error:
        print("ERROR: Patched app.py did not pass syntax check:", error)
        return 1

    if app_updated == app_source and html_updated == index_source:
        print("ALREADY INSTALLED: no files changed.")
        return 0

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    app_backup = APP_PATH.with_name(f"app_before_baseline_{timestamp}.py")
    index_backup = INDEX_PATH.with_name(f"index_before_baseline_{timestamp}.html")

    shutil.copy2(APP_PATH, app_backup)
    shutil.copy2(INDEX_PATH, index_backup)

    try:
        APP_PATH.write_text(app_updated, encoding="utf-8")
        INDEX_PATH.write_text(html_updated, encoding="utf-8")
    except OSError as error:
        # Restore originals in the unlikely event a write fails.
        shutil.copy2(app_backup, APP_PATH)
        shutil.copy2(index_backup, INDEX_PATH)
        print("ERROR: Installation failed; original files restored:", error)
        return 1

    print("INSTALLATION SUCCESSFUL")
    print(f"app.py backup  : {app_backup.name}")
    print(f"index backup   : {index_backup.name}")
    print("Baseline API   : http://127.0.0.1:5000/api/baselines")
    print("Refresh browser with Ctrl+Shift+R after restarting the N3 system.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

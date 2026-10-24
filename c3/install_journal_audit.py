"""Safe additive installer for N3_TIVE Journal & Audit.

Run from N3_TIVE project root:
    python install_journal_audit.py

Backs up existing Flask app and HTML; retains other working features.
"""

from datetime import datetime
from pathlib import Path
import ast
import py_compile
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path.cwd()
APP_FILE = ROOT / "dashboard" / "app.py"
HTML_FILE = ROOT / "dashboard" / "templates" / "index.html"
NEW_API = ROOT / "dashboard" / "journal_audit_api.py"
NEW_JS = ROOT / "dashboard" / "static" / "js" / "journal_audit.js"
SRC_API = HERE / "dashboard" / "journal_audit_api.py"
SRC_JS = HERE / "dashboard" / "static" / "js" / "journal_audit.js"
IMPORT_MARKER = "# N3 JOURNAL & AUDIT BLUEPRINT REGISTRATION"
SCRIPT_MARKER = "filename='js/journal_audit.js'"


def fail(message):
    print(f"INSTALLATION STOPPED: {message}")
    sys.exit(1)


def main():
    for path in (APP_FILE, HTML_FILE, SRC_API, SRC_JS):
        if not path.is_file():
            fail(f"Missing file: {path}")

    # Verify generated Python before copying it.
    ast.parse(SRC_API.read_text(encoding="utf-8"))
    original_app = APP_FILE.read_text(encoding="utf-8")
    original_html = HTML_FILE.read_text(encoding="utf-8")

    app_updated = original_app
    html_updated = original_html

    if IMPORT_MARKER not in app_updated:
        import re
        match = re.search(r"(?m)^if\s+__name__\s*==\s*(['\"])__main__\1\s*:\s*$", app_updated)
        if not match:
            fail("Cannot find the usual app.py startup block. No files changed.")
        registration = (
            "\n" + IMPORT_MARKER + "\n"
            "if __package__:\n"
            "    from .journal_audit_api import journal_audit_bp\n"
            "else:\n"
            "    from journal_audit_api import journal_audit_bp\n"
            "\n"
            "app.register_blueprint(journal_audit_bp)\n\n\n"
        )
        app_updated = app_updated[:match.start()] + registration + app_updated[match.start():]

    if SCRIPT_MARKER not in html_updated:
        if "</body>" not in html_updated:
            fail("Cannot find </body> in index.html. No files changed.")
        include = (
            "\n<!-- N3 Journal & Audit (read-only) -->\n"
            "<script src=\"{{ url_for('static', filename='js/journal_audit.js') }}\"></script>\n"
        )
        html_updated = html_updated.replace("</body>", include + "</body>", 1)

    # A syntax error in the proposed app must not damage the existing app.
    ast.parse(app_updated)
    import time
    backup_dir = ROOT / "backups" / (
        "journal_audit_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    backup_dir.mkdir(parents=True, exist_ok=False)
    for target in (APP_FILE, HTML_FILE, NEW_API, NEW_JS):
        if target.exists():
            destination = backup_dir / target.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, destination)

    try:
        NEW_JS.parent.mkdir(parents=True, exist_ok=True)
        # After extraction into the project root, source and target are
        # normally the same file. Avoid shutil.SameFileError.
        if SRC_API.resolve() != NEW_API.resolve():
            shutil.copy2(SRC_API, NEW_API)
        if SRC_JS.resolve() != NEW_JS.resolve():
            shutil.copy2(SRC_JS, NEW_JS)
        APP_FILE.write_text(app_updated, encoding="utf-8")
        HTML_FILE.write_text(html_updated, encoding="utf-8")
        py_compile.compile(str(APP_FILE), doraise=True)
        py_compile.compile(str(NEW_API), doraise=True)
    except Exception:
        # The baseline/dashboard remain safe in case of a failed installation.
        APP_FILE.write_text(original_app, encoding="utf-8")
        HTML_FILE.write_text(original_html, encoding="utf-8")
        raise

    print("============================================")
    print("N3 JOURNAL & AUDIT INSTALLATION SUCCESSFUL")
    print("============================================")
    print(f"Backup folder : {backup_dir}")
    print(f"Flask API     : {NEW_API}")
    print(f"Frontend JS   : {NEW_JS}")
    print("API endpoint  : http://127.0.0.1:5000/api/journal-audit")
    print("Next: Restart run_n3.py, then Ctrl+Shift+R in the browser.")


if __name__ == "__main__":
    main()

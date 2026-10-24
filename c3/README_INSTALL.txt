N3_TIVE Journal & Audit — Additive Installation
===============================================

This package adds report-derived journal and audit visibility. It does NOT
change NFC reading, verdict calculations, saved baselines, existing journal
records, the verification database, or the already-installed Scan History and
Baseline Management views.

INSTALL (Windows PowerShell):

1. Keep a backup of the project. Close the running N3 system with Ctrl+C.
2. Download this ZIP file to your Windows Downloads folder.
3. Run PowerShell inside the N3_TIVE project root.

4. Extract directly into the project root:
   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\N3_Journal_Audit.zip" -DestinationPath "." -Force

5. Run the additive installer:
   python install_journal_audit.py

6. Restart:
   python run_n3.py --port COM9

7. Test in browser:
   http://127.0.0.1:5000/api/journal-audit
   http://127.0.0.1:5000/
   Press Ctrl+Shift+R and click Journal & Audit.

8. Expected: Saved verification reports appear with journal status,
   verdict, rollback, baseline version and a View evidence action.
   Empty/no status values are displayed as NOT_EVALUATED or --.

9. If the new endpoint returns 404, confirm that app.py was patched and
   restart the N3 process. Do not run two Flask servers on port 5000.

BACKUPS:
   backups/journal_audit_YYYYMMDD_HHMMSS/
The installer keeps timestamped backups of app.py and index.html.

IMPORTANT SECURITY NOTE:
The module is READ-ONLY and intentionally omits raw memory bytes, secret
keys and stored HMAC values from its API. Audit events are derived from
saved N3_REPORT_*.json verification reports; this is not a cryptographically
immutable log and does not establish the exact external modification time.

The real SQLite journal/audit table event feed needs database table schema
from journal_manager.py for correct direct integration. This version does
not pretend saved reports are authenticated journal database entries.

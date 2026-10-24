"""Install the simple Viva-1 N1 dashboard without changing NFC data or configs.csv."""
from __future__ import annotations
from pathlib import Path
from datetime import datetime
import shutil, sys

root = Path(__file__).resolve().parent
dash = root / "N1_Auto_Dashboard"
backend = dash / "n1_dashboard.py"
frontend = dash / "dashboard.html"
module_src = root / "n1_observed_score.py"
html_src = root / "simple_dashboard.html"
if any(not p.is_file() for p in (backend, frontend, module_src, html_src)):
    sys.exit("INSTALL BLOCKED: required files missing. Run from N1 Implementation root after copying all upgrade files.")
text = backend.read_text(encoding="utf-8-sig")
marker = "OBSERVED_FACTOR_AVERAGE_V1"
if marker in text:
    sys.exit("SIMPLE VIVA DASHBOARD ALREADY INSTALLED: no changes made.")

# Import is inserted near the existing n1_core import and works with either V1/V2 risk patch.
needle = "from n1_core import "
if text.count(needle) != 1:
    sys.exit("INSTALL BLOCKED: unexpected backend import layout. No files changed.")
text = text.replace(needle, "from n1_observed_score import score_known_card  # " + marker + "\n" + needle, 1)

# State field.
needle = "        self.risk_score = None"
if text.count(needle) != 1:
    sys.exit("INSTALL BLOCKED: risk state field not found. No files changed.")
text = text.replace(needle, needle + "\n        self.observed_score = None", 1)

# Calculate after parse. Keep any old heuristic scoring untouched but no longer primary UI.
needle = "        card = parse_nfc_text(text, source=source)"
if text.count(needle) != 1:
    sys.exit("INSTALL BLOCKED: card parse point not found. No files changed.")
text = text.replace(needle, needle + "\n        observed_score = score_known_card(card, PROJECT)", 1)

# Save in state.
needle = "            self.card = public_card(card)"
if text.count(needle) != 1:
    sys.exit("INSTALL BLOCKED: card state point not found. No files changed.")
text = text.replace(needle, needle + "\n            self.observed_score = observed_score", 1)

# Export via API.
needle = '                "risk_score": self.risk_score,'
if text.count(needle) != 1:
    sys.exit("INSTALL BLOCKED: API risk field not found. No files changed.")
text = text.replace(needle, needle + '\n                "observed_score": self.observed_score,', 1)

try:
    compile(text, str(backend), "exec")
    compile(module_src.read_text(encoding="utf-8-sig"), str(module_src), "exec")
except Exception as exc:
    sys.exit("INSTALL BLOCKED: validation failed: " + str(exc))

backup = dash / ("simple_viva_backup_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
backup.mkdir(parents=True, exist_ok=False)
for p in (backend, frontend):
    shutil.copy2(p, backup / p.name)
try:
    shutil.copy2(module_src, dash / "n1_observed_score.py")
    backend.write_text(text, encoding="utf-8")
    shutil.copy2(html_src, frontend)
except Exception as exc:
    shutil.copy2(backup / backend.name, backend)
    shutil.copy2(backup / frontend.name, frontend)
    sys.exit("INSTALL FAILED: original dashboard restored. " + str(exc))

print("N1 SIMPLE VIVA DASHBOARD: INSTALLED")
print("PRIMARY SCORE: OBSERVED-FACTOR AVERAGE (0 / 0.5 / 1)")
print("UNKNOWN: EXCLUDED FROM SCORE, REDUCES COVERAGE")
print("NOT APPLICABLE: EXCLUDED FROM SCORE AND COVERAGE")
print("EVIDENCE COVERAGE: ENABLED")
print("FINAL COX SCORE: PENDING ON MAIN SCREEN")
print("COX DEMO: KEPT SEPARATE IF INSTALLED")
print("TECHNICAL DETAILS: COLLAPSED BY DEFAULT")
print("ORIGINAL DASHBOARD: BACKED UP")
print("NO NFC WRITE PERFORMED")

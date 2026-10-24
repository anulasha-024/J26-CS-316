N1 VIVA-1 0-100 RISK EXPOSURE INDEX — OCT 2026

WHAT THIS IS:
- A non-calibrated, deterministic pilot scoring index using real Flipper Zero scan evidence.
- Existing N1_Auto_Dashboard read-only USB collector is preserved.
- NTAG215 uses observed AUTH0, CC, static/dynamic lock and ACCESS/PROT pages.
- MIFARE Classic 1K uses captured readable blocks + matching sector key records;
  if key evidence is unavailable the UI shows UNKNOWN rather than making up a score.
- Shows LOW / MEDIUM / HIGH exposure categories and each factor's explicit points.
- Does NOT modify tags, calculate Cox hazard ratios, or turn scan times into TTC.

HOW TO INSTALL:
1. Close the running dashboard in the PowerShell terminal (Ctrl+C).
2. Extract the TWO .py files from the ZIP into your project root:
   C:\Users\Dahami\Desktop\N1 Implementation\
   IMPORTANT: they go in the same folder as your Datasets and N1_Auto_Dashboard folders.
3. In that root folder run: py .\APPLY_N1_RISK_SCORE.py
4. Restart: py .\N1_Auto_Dashboard\n1_dashboard.py --port COM3 --open-now
5. Present NTAG215_02 to Flipper for a REAL USB scan; look for Risk Exposure Index.

If current Flipper dump does not include page 131/132, NO numeric score is shown,
which is correct. Use the captured evidence and don't fabricate a result.
Do not enable AUTH0 write protection: external password backup/recovery still pending.

WARNING ABOUT LABELS:
0-100 is a manually selected *policy exposure index* for Viva 1 only,
not a calibrated exploitability prediction or validated probability.
The original proposal's scientific novelty is deriving proper weights later
from time-to-compromise/Cox on sufficiently varied experiments (Viva 2).
T2 is a context label because current hardware is Flipper Zero, not a
separately estimated T2 risk coefficient.

To restore prior dashboard files, copy n1_dashboard.py and dashboard.html from
N1_Auto_Dashboard/score_patch_backup_YYYYMMDD_HHMMSS/ over updated versions
and delete N1_Auto_Dashboard/n1_scoring.py (only if it didn't exist before).

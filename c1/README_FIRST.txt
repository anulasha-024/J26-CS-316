N1 VIVA-1 SIMPLE DASHBOARD
===========================
Purpose: make the main Viva dashboard easy to explain.

MAIN SCREEN ONLY SHOWS:
1. Known Card ID / Card Type / UID
2. Observed-Factor Risk Score
3. Evidence Coverage
4. Preliminary Baseline Score
5. Final Cox Score = Pending

The six-factor calculation is hidden under "Show calculation (only if panel asks)".
Cox model details stay on the separate /cox-demo page if that demo is installed.

SCORING RULES ARE NOT CHANGED:
- known factor risk values = 0 / 0.5 / 1
- UNKNOWN: excluded from score, but reduces Evidence Coverage
- Not Applicable: excluded from both score and coverage denominator
- score = average of known applicable factor values * 100

INSTALL:
1. Stop dashboard (Ctrl+C)
2. Copy all files in this package into the N1 Implementation root folder
3. Run:
   py .\SELFTEST_SIMPLE_VIVA.py
   py .\INSTALL_SIMPLE_VIVA_DASHBOARD.py
4. Restart:
   py ".\N1_Auto_Dashboard\n1_dashboard.py" --port COM3 --open-now

IMPORTANT:
The current known UID mapping in the scoring module includes the two confirmed NTAG215 lab cards.
For MIFARE Classic, an exact UID must exist in configs.csv (uid/card_uid column) or a confirmed registry mapping must be added. The installer deliberately does not guess the unresolved MIFARE_01/MIFARE_02 mapping.
No NFC writes are performed.

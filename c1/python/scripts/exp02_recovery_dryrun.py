from pathlib import Path
import os
import re

ROOT = Path(__file__).resolve().parents[2]

capture = ROOT / "python/raw_data/NTAG215_02_PRECONFIG_CAPTURE.nfc"
report = ROOT / "results/Reports/EXP02_Recovery_Dry_Run.txt"

vault = Path(os.environ["LOCALAPPDATA"]) / "N1_Research_Private"
secret = vault / "NTAG215_02_PWD.txt"

if not capture.is_file():
    raise RuntimeError("ORIGINAL CAPTURE MISSING")

if not secret.is_file():
    raise RuntimeError("ENCRYPTED PASSWORD FILE MISSING")

data = capture.read_text(
    encoding="utf-8-sig",
    errors="replace"
)

uid_match = re.search(
    r"^UID:\s*([0-9A-Fa-f ]+)\s*$",
    data,
    re.MULTILINE
)

if not uid_match:
    raise RuntimeError("UID NOT FOUND")

uid = uid_match.group(1).replace(" ", "").upper()

if uid != "04A3C090310289":
    raise RuntimeError("WRONG CARD BASELINE")


def read_saved_page(number):
    match = re.search(
        rf"^Page\s+{number}:\s*"
        rf"([0-9A-Fa-f]{{2}}(?:\s+[0-9A-Fa-f]{{2}}){{3}})\s*$",
        data,
        re.MULTILINE
    )

    if not match:
        raise RuntimeError(f"PAGE {number} MISSING")

    return bytes.fromhex(match.group(1))


expected = {
    2: "2A480000",
    130: "000000BD",
    131: "040000FF",
    132: "00050000",
}

for page, value in expected.items():
    if read_saved_page(page) != bytes.fromhex(value):
        raise RuntimeError(
            f"PAGE {page} BASELINE MISMATCH"
        )

original_config = read_saved_page(131)

# Offline preparation only.
restore_frame = bytes([0xA2, 0x83]) + original_config

if restore_frame.hex().upper() != "A283040000FF":
    raise RuntimeError("RESTORE FRAME INVALID")

report.parent.mkdir(parents=True, exist_ok=True)

report.write_text(
    "N1 EXP-02 RECOVERY DRY RUN\n"
    "UID: 04A3C090310289\n"
    "Baseline identity: VERIFIED\n"
    "Original AUTH0: FF\n"
    "Planned experiment AUTH0: 04\n"
    "Original configuration: VERIFIED\n"
    "Recovery frame: PREPARED OFFLINE\n"
    "Encrypted password file: PRESENT\n"
    "Protected recovery: NOT YET TESTED\n"
    "No NFC commands executed\n",
    encoding="utf-8"
)

print("CARD BASELINE: VERIFIED")
print("ORIGINAL CONFIGURATION: VERIFIED")
print("ENCRYPTED PASSWORD FILE: FOUND")
print("RECOVERY FRAME: PREPARED OFFLINE")
print("RECOVERY REPORT: SAVED")
print("NO NFC WRITE PERFORMED")


import ctypes
import hashlib
import os
import shutil
from pathlib import Path

source = (
    Path(os.environ["LOCALAPPDATA"])
    / "N1_Research_Private"
    / "NTAG215_02_PORTABLE_BACKUP_V2.txt"
)

if not source.is_file():
    raise SystemExit("ENCRYPTED BACKUP SOURCE: NOT FOUND")

print("ENCRYPTED BACKUP SOURCE: FOUND")

kernel32 = ctypes.windll.kernel32

drives = [
    Path(f"{letter}:\\")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if kernel32.GetDriveTypeW(f"{letter}:\\") == 2
]

if not drives:
    print("REMOVABLE USB DRIVE: NOT FOUND")
    print("EXTERNAL BACKUP: PENDING")

elif len(drives) > 1:
    print("MULTIPLE REMOVABLE DRIVES FOUND")
    print("EXTERNAL BACKUP: PENDING")

else:
    folder = drives[0] / "N1_Research_Encrypted_Backup"
    destination = folder / source.name

    source_hash = hashlib.sha256(
        source.read_bytes()
    ).hexdigest()

    if destination.exists():
        destination_hash = hashlib.sha256(
            destination.read_bytes()
        ).hexdigest()

        if destination_hash != source_hash:
            raise SystemExit(
                "EXISTING BACKUP DIFFERS - NOT OVERWRITTEN"
            )

    else:
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    copied_hash = hashlib.sha256(
        destination.read_bytes()
    ).hexdigest()

    if source_hash != copied_hash:
        raise SystemExit("BACKUP HASH MISMATCH")

    print("EXTERNAL BACKUP: VERIFIED")
    print("SHA256 INTEGRITY: PASSED")

print("NO NFC WRITE PERFORMED")
print("COX CALIBRATION: NOT READY")

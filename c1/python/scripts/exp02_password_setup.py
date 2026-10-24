import re
import subprocess
import sys
import time
from pathlib import Path

import serial

sys.path.insert(0, str(Path(__file__).resolve().parent))
import flipper_auto_timing as a

EXPECTED_UID = "04A3C090310289"


def get_private_password():
    ps = r'''
$ErrorActionPreference = "Stop"
$f = Join-Path $env:LOCALAPPDATA "N1_Research_Private\NTAG215_02_PWD.txt"
$s = Get-Content $f | ConvertTo-SecureString
$p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
try {
    [Console]::Out.Write(
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)
    )
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p)
}
'''
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-Command", ps],
        capture_output=True,
        text=True,
        check=True
    )

    password = result.stdout.strip().upper()

    if not re.fullmatch(r"[0-9A-F]{8}", password):
        raise RuntimeError("Invalid stored password")

    if password == "FFFFFFFF":
        raise RuntimeError("Default password is not permitted")

    return password


def read_page(ser, number):
    response = a.send_nfc_command(
        ser, f"mfu rdbl -b {number}", timeout=5
    )
    value = a.extract_block_data(response, number)

    if value is None:
        raise RuntimeError(f"Cannot read Page {number}")

    return bytes.fromhex(value)


def main():
    if "--program-password" not in sys.argv:
        print("SCRIPT READY - NO NFC WRITE PERFORMED")
        return

    with serial.Serial(a.PORT, a.BAUD, timeout=0.1) as ser:
        time.sleep(1)
        a.collect_serial_output(ser, timeout=0.5)

        ser.write(b"nfc\r")
        ser.flush()

        if "[nfc]>:" not in a.read_until_prompt(
            ser, "[nfc]>:", timeout=5
        ):
            raise RuntimeError("NFC CLI unavailable")

        try:
            p0 = read_page(ser, 0)
            p1 = read_page(ser, 1)
            p2 = read_page(ser, 2)

            uid = (p0[:3] + p1).hex().upper()

            bcc0 = 0x88 ^ p0[0] ^ p0[1] ^ p0[2]
            bcc1 = p1[0] ^ p1[1] ^ p1[2] ^ p1[3]

            if (
                uid != EXPECTED_UID
                or p0[3] != bcc0
                or p2[0] != bcc1
            ):
                raise RuntimeError("UID SAFETY CHECK FAILED")

            print("UID VERIFIED:", uid)

            if (
                read_page(ser, 131) != bytes.fromhex("04 00 00 FF")
                or read_page(ser, 132) != bytes.fromhex("00 05 00 00")
            ):
                raise RuntimeError(
                    "CONFIGURATION MISMATCH - NO WRITE"
                )

            print("UNPROTECTED CONFIGURATION VERIFIED")

            password = get_private_password()

            # Program PWD only. AUTH0 remains FF.
            response = a.send_nfc_command(
                ser,
                f"raw -p 14a -s -c -d A285{password}",
                timeout=5
            )

            if "Error:" in response:
                raise RuntimeError("Password write command failed")

            # Validate new password using PWD_AUTH.
            response = a.send_nfc_command(
                ser,
                f"raw -p 14a -s -c -d 1B{password}",
                timeout=5
            )

            match = re.search(
                r"Rx:\s*((?:[0-9A-Fa-f]{2}\s*)+)",
                response
            )

            if not match:
                raise RuntimeError(
                    "Authentication response unavailable"
                )

            received = bytes.fromhex(match.group(1))

            if len(received) < 4 or received[:2] != b"\x00\x00":
                raise RuntimeError(
                    "Custom password authentication not verified"
                )

            if read_page(ser, 131)[3] != 0xFF:
                raise RuntimeError(
                    "AUTH0 unexpectedly changed"
                )

            print("CUSTOM PASSWORD AUTHENTICATION: PASSED")
            print("AUTH0: FF - PROTECTION STILL DISABLED")
            print("PASSWORD VALUE: NOT DISPLAYED")

        finally:
            ser.write(b"exit\r")
            ser.flush()


if __name__ == "__main__":
    main()

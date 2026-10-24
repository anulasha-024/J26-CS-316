import json
import re
import time
from datetime import datetime
from pathlib import Path

import serial


# ============================================================
# N1 - Live NFC Card Scanner
# Device: Flipper Zero
# Attacker Tier: T2
# ============================================================

PORT = "COM3"
BAUD_RATE = 115200

STATUS_FILE = Path(__file__).with_name("live_card_status.json")


# ------------------------------------------------------------
# Known laboratory cards
# ------------------------------------------------------------

KNOWN_CARDS = {
    "04 03 72 A0 31 02 89": {
        "card_id": "NTAG215_01",
        "family": "NTAG215",
    },

    "04 A3 C0 90 31 02 89": {
        "card_id": "NTAG215_02",
        "family": "NTAG215",
    },

    "B7 95 66 5F": {
        "card_id": "MIFARE1K_01",
        "family": "MIFARE Classic 1K",
    },

    "B7 22 FD 5F": {
        "card_id": "MIFARE1K_02",
        "family": "MIFARE Classic 1K",
    },
}


ANSI_ESCAPE = re.compile(
    rb"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)


def clean_output(data: bytes) -> str:
    data = ANSI_ESCAPE.sub(b"", data)

    return data.decode(
        "utf-8",
        errors="ignore",
    ).replace("\r", "")


def normalize_uid(uid: str) -> str:
    values = re.findall(
        r"\b[0-9A-Fa-f]{2}\b",
        uid,
    )

    return " ".join(
        value.upper()
        for value in values
    )


def clear_serial_buffer(ser):
    time.sleep(0.2)

    if ser.in_waiting:
        ser.read(
            ser.in_waiting
        )


def send_command(ser, command: str):
    ser.write(
        (command + "\r\n").encode()
    )

    ser.flush()


def read_until(
    ser,
    expected=None,
    timeout=10,
):
    start = time.monotonic()
    data = b""

    while time.monotonic() - start < timeout:

        waiting = ser.in_waiting

        if waiting:
            chunk = ser.read(waiting)
            data += chunk

            text = clean_output(data)

            if expected:

                if isinstance(
                    expected,
                    (list, tuple),
                ):

                    for item in expected:
                        if item.lower() in text.lower():
                            return text

                elif expected.lower() in text.lower():
                    return text

        time.sleep(0.05)

    return clean_output(data)


def read_until_idle(
    ser,
    timeout=5,
    idle_time=0.8,
):
    start = time.monotonic()
    last_data = time.monotonic()

    data = b""

    while time.monotonic() - start < timeout:

        waiting = ser.in_waiting

        if waiting:
            chunk = ser.read(waiting)
            data += chunk
            last_data = time.monotonic()

        elif (
            data
            and
            time.monotonic() - last_data
            >= idle_time
        ):
            break

        time.sleep(0.05)

    return clean_output(data)


def extract_dump_path(text: str):

    match = re.search(
        r"Dump saved to\s+['\"]([^'\"]+\.nfc)['\"]",
        text,
        re.IGNORECASE,
    )

    if match:
        return match.group(1)

    return None


def extract_uid_from_file(
    file_text: str,
    protocol_text: str,
):

    # --------------------------------------------------------
    # Method 1:
    # Flipper .nfc file directly contains UID:
    # --------------------------------------------------------

    for line in file_text.splitlines():

        if line.strip().lower().startswith("uid:"):

            uid = normalize_uid(line)

            if uid:
                return uid

    # --------------------------------------------------------
    # Method 2:
    # MIFARE Classic
    # First 4 bytes of Block 0 = UID
    # --------------------------------------------------------

    if "mifare classic" in (
        protocol_text + file_text
    ).lower():

        match = re.search(
            r"Block\s+0\s*:\s*"
            r"((?:[0-9A-Fa-f]{2}\s+){3}"
            r"[0-9A-Fa-f]{2})",
            file_text,
            re.IGNORECASE,
        )

        if match:
            values = re.findall(
                r"\b[0-9A-Fa-f]{2}\b",
                match.group(1),
            )

            if len(values) >= 4:

                return " ".join(
                    value.upper()
                    for value in values[:4]
                )

    # --------------------------------------------------------
    # Method 3:
    # NTAG / Type 2 memory layout
    #
    # Page 0:
    # UID0 UID1 UID2 BCC0
    #
    # Page 1:
    # UID3 UID4 UID5 UID6
    # --------------------------------------------------------

    page0 = re.search(
        r"(?:Page|Block)\s+0\s*:\s*"
        r"((?:[0-9A-Fa-f]{2}\s+){3}"
        r"[0-9A-Fa-f]{2})",
        file_text,
        re.IGNORECASE,
    )

    page1 = re.search(
        r"(?:Page|Block)\s+1\s*:\s*"
        r"((?:[0-9A-Fa-f]{2}\s+){3}"
        r"[0-9A-Fa-f]{2})",
        file_text,
        re.IGNORECASE,
    )

    if page0 and page1:

        p0 = re.findall(
            r"\b[0-9A-Fa-f]{2}\b",
            page0.group(1),
        )

        p1 = re.findall(
            r"\b[0-9A-Fa-f]{2}\b",
            page1.group(1),
        )

        if (
            len(p0) >= 4
            and
            len(p1) >= 4
        ):

            uid_bytes = [
                p0[0],
                p0[1],
                p0[2],
                p1[0],
                p1[1],
                p1[2],
                p1[3],
            ]

            return " ".join(
                value.upper()
                for value in uid_bytes
            )

    return None


def detect_family(
    uid,
    dump_output,
    file_text,
):

    # Known lab card
    if uid in KNOWN_CARDS:

        return KNOWN_CARDS[uid][
            "family"
        ]

    combined = (
        dump_output
        + "\n"
        + file_text
    ).lower()

    if "mifare classic" in combined:

        if "1k" in combined:
            return "MIFARE Classic 1K"

        return "MIFARE Classic"

    if (
        "ntag215" in combined
        or
        "ntag 215" in combined
    ):
        return "NTAG215"

    if (
        "mifare ultralight" in combined
        or
        "ntag" in combined
    ):
        return "Type 2 / NTAG"

    return "Unknown NFC Card"


def save_live_status(
    uid,
    family,
    dump_path,
):

    known = uid in KNOWN_CARDS

    if known:

        card_id = KNOWN_CARDS[uid][
            "card_id"
        ]

        status = "KNOWN LAB CARD"

    else:

        card_id = "UNKNOWN"

        status = "UNKNOWN CARD"

    result = {
        "detected": True,
        "card_id": card_id,
        "uid": uid,
        "family": family,
        "tier": "T2 - Flipper Zero",
        "status": status,
        "known_card": known,
        "timestamp": datetime.now()
        .astimezone()
        .isoformat(
            timespec="seconds"
        ),
        "dump_path": dump_path,
    }

    with open(
        STATUS_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            result,
            file,
            indent=4,
        )

    return result


def scan_card(ser):

    print()
    print(
        "Scanning NFC card..."
    )

    clear_serial_buffer(ser)

    # --------------------------------------------------------
    # Enter NFC CLI
    # --------------------------------------------------------

    send_command(
        ser,
        "nfc",
    )

    nfc_output = read_until(
        ser,
        expected=[
            "Welcome to NFC Command Line Interface",
            "NFC",
        ],
        timeout=5,
    )

    # --------------------------------------------------------
    # Dump current card
    # This READS the card.
    # It does NOT write to the NFC card.
    # --------------------------------------------------------

    send_command(
        ser,
        "dump",
    )

    dump_output = read_until(
        ser,
        expected=[
            "Dump saved to",
            "No card",
            "Failed",
            "Error",
        ],
        timeout=25,
    )

    print(
        dump_output.strip()
    )

    dump_path = extract_dump_path(
        dump_output
    )

    # Leave NFC CLI
    send_command(
        ser,
        "exit",
    )

    read_until_idle(
        ser,
        timeout=3,
    )

    if not dump_path:

        print()
        print(
            "No readable card detected."
        )

        return None

    # --------------------------------------------------------
    # Read dump file from Flipper storage
    # --------------------------------------------------------

    send_command(
        ser,
        f"storage read {dump_path}",
    )

    file_text = read_until_idle(
        ser,
        timeout=8,
        idle_time=1.0,
    )

    uid = extract_uid_from_file(
        file_text,
        dump_output,
    )

    if not uid:

        print()
        print(
            "Card detected, but UID "
            "could not be parsed."
        )

        return None

    family = detect_family(
        uid,
        dump_output,
        file_text,
    )

    result = save_live_status(
        uid,
        family,
        dump_path,
    )

    print()
    print(
        "=" * 55
    )

    print(
        "LIVE CARD DETECTED"
    )

    print(
        "=" * 55
    )

    print(
        f"Card ID : "
        f"{result['card_id']}"
    )

    print(
        f"UID     : "
        f"{result['uid']}"
    )

    print(
        f"Family  : "
        f"{result['family']}"
    )

    print(
        f"Tier    : "
        f"{result['tier']}"
    )

    print(
        f"Status  : "
        f"{result['status']}"
    )

    print(
        f"Time    : "
        f"{result['timestamp']}"
    )

    print(
        "=" * 55
    )

    print()
    print(
        "Dashboard status file updated:"
    )

    print(
        STATUS_FILE
    )

    return result


def main():

    print()
    print(
        "N1 LIVE NFC CARD SCANNER"
    )

    print(
        "Flipper Zero - T2"
    )

    print(
        "-" * 55
    )

    print(
        f"Serial Port : {PORT}"
    )

    print(
        f"Baud Rate   : "
        f"{BAUD_RATE}"
    )

    print()

    try:

        ser = serial.Serial(
            PORT,
            BAUD_RATE,
            timeout=0.1,
        )

    except serial.SerialException as error:

        print(
            "ERROR: Cannot open COM3."
        )

        print()
        print(
            "Close Flipper Lab, "
            "Miniterm, and any other "
            "program using COM3."
        )

        print()
        print(
            error
        )

        return

    time.sleep(1)

    clear_serial_buffer(
        ser
    )

    try:

        while True:

            print()
            print(
                "Place one NFC card on "
                "the Flipper Zero."
            )

            user_input = input(
                "Press ENTER to scan "
                "(Q = quit): "
            ).strip().lower()

            if user_input == "q":
                break

            scan_card(
                ser
            )

    except KeyboardInterrupt:

        print()
        print(
            "Scanner stopped."
        )

    finally:

        ser.close()

        print()
        print(
            "COM3 released."
        )


if __name__ == "__main__":
    main()
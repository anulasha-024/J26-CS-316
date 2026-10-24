import time
import serial

from flipper_auto_timing import (
    PORT,
    BAUD,
    collect_serial_output,
    read_until_prompt,
    send_nfc_command,
    extract_block_data,
)

EXPECTED_UID = "04A3C090310289"

with serial.Serial(PORT, BAUD, timeout=0.1) as ser:
    time.sleep(1)
    collect_serial_output(ser, timeout=0.5)

    ser.reset_input_buffer()
    ser.write(b"nfc\r")
    ser.flush()

    if "[nfc]>:" not in read_until_prompt(ser, "[nfc]>:", 5):
        raise RuntimeError("Could not enter NFC CLI")

    try:
        pages = {}

        for n in (0, 1, 2):
            output = send_nfc_command(
                ser, f"mfu rdbl -b {n}", timeout=5
            )
            data = extract_block_data(output, n)

            if data is None:
                raise RuntimeError(f"Page {n} read failed")

            pages[n] = bytes.fromhex(data)

        uid = (pages[0][:3] + pages[1]).hex().upper()

        bcc0 = 0x88
        for byte in pages[0][:3]:
            bcc0 ^= byte

        bcc1 = 0
        for byte in pages[1]:
            bcc1 ^= byte

        valid = (
            uid == EXPECTED_UID
            and pages[0][3] == bcc0
            and pages[2][0] == bcc1
        )

        print("Detected UID:", uid)
        print("Expected UID:", EXPECTED_UID)
        print(
            "HARDWARE UID GUARD:",
            "PASSED" if valid else "FAILED"
        )

    finally:
        ser.write(b"exit\r")
        ser.flush()


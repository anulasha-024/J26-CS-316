from pathlib import Path
import re
import time
import serial

PORT = "COM3"
REMOTE = "/ext/nfc/N1_MIFARE_02_TEST.nfc"

print("N1 MIFARE Classic Dump Copy")
print("--------------------------")

try:
    with serial.Serial(PORT, 115200, timeout=0.2) as ser:
        ser.write(b"\r")
        time.sleep(0.5)
        ser.reset_input_buffer()

        ser.write(f"storage read {REMOTE}\r".encode())
        ser.flush()

        data = bytearray()
        deadline = time.monotonic() + 25
        last_data = time.monotonic()

        while time.monotonic() < deadline:
            chunk = ser.read(ser.in_waiting or 1)

            if chunk:
                data.extend(chunk)
                last_data = time.monotonic()
            elif (
                b"Block 63:" in data
                and time.monotonic() - last_data > 1
            ):
                break

    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    start = re.search(
        r"(?m)^Filetype:\s*Flipper NFC device\s*$",
        text
    )

    if not start:
        raise ValueError("NFC file header not received")

    content = text[start.start():]

    blocks = re.findall(r"(?m)^Block (\d+):", content)
    numbers = {int(block) for block in blocks}

    if numbers != set(range(64)):
        raise ValueError(
            f"Incomplete dump: {len(numbers)}/64 blocks"
        )

    last = re.search(r"(?m)^Block 63:.*$", content)
    content = content[:last.end()] + "\n"

    uid_match = re.search(
        r"(?m)^UID:\s*([0-9A-Fa-f ]+)",
        content
    )

    uid = (
        uid_match.group(1).replace(" ", "").upper()
        if uid_match else "UNKNOWN"
    )

    folder = Path(__file__).resolve().parent / "python" / "raw_data"
    folder.mkdir(parents=True, exist_ok=True)

    target = folder / f"MIFARE_{uid}_READONLY_DUMP.nfc"
    number = 2

    while target.exists():
        target = folder / f"MIFARE_{uid}_READONLY_DUMP_{number}.nfc"
        number += 1

    target.write_text(content, encoding="utf-8")

    print("SUCCESS: MIFARE dump copied!")
    print(f"Blocks: {len(numbers)}/64")
    print(f"UID: {uid}")
    print(f"Saved to: {target}")

except Exception as error:
    print(f"ERROR: {error}")
    print("Check COM3 and close Dashboard/Miniterm.")



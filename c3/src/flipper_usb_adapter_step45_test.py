from pathlib import Path
from datetime import datetime, timezone

import argparse
import hashlib
import json
import re
import time

import serial


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

INCOMING_DIR = (
    PROJECT_ROOT
    / "data"
    / "incoming"
)

RUNTIME_STATE_PATH = (
    PROJECT_ROOT
    / "data"
    / "n3_runtime_state.json"
)


# --------------------------------------------------
# N3 LIVE RUNTIME STATE
# --------------------------------------------------

def write_runtime_state(
    status,
    message,
    **extra
):
    """
    Publish the current Flipper/N3 acquisition state
    for the live dashboard.

    The state file is written atomically so the
    dashboard never reads partially written JSON.
    """

    RUNTIME_STATE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    payload = {
        "status":
            status,

        "message":
            message,

        "updated_at_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),
    }

    payload.update(
        extra
    )

    temporary_path = (
        RUNTIME_STATE_PATH.with_suffix(
            ".tmp"
        )
    )

    temporary_path.write_text(
        json.dumps(
            payload,
            indent=4
        ),
        encoding="utf-8"
    )

    temporary_path.replace(
        RUNTIME_STATE_PATH
    )


# --------------------------------------------------
# FLIPPER USB CONFIGURATION
# --------------------------------------------------

DEFAULT_PORT = "COM9"

BAUD_RATE = 230400

SERIAL_READ_TIMEOUT = 0.02

DEFAULT_SCAN_TIMEOUT_MS = 5000

# Keep completed result visible before the next
# continuous acquisition attempt starts.
POST_SCAN_COOLDOWN = 0.5


# --------------------------------------------------
# ANSI ESCAPE CLEANUP
# --------------------------------------------------

ANSI_ESCAPE_PATTERN = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)


def remove_ansi_escape_codes(
    text
):
    """
    Remove ANSI colour/control sequences returned
    by the Flipper CLI.
    """

    return ANSI_ESCAPE_PATTERN.sub(
        "",
        text
    )


# --------------------------------------------------
# CHECK WHETHER OUTPUT ENDS WITH REAL CLI PROMPT
# --------------------------------------------------

def output_ends_with_prompt(
    text
):
    """
    Detect only an actual completed CLI prompt.

    Command echo such as:

        >: nfc

    must not be mistaken for the final prompt.

    Real prompts:

        >:
        nfc>:
        [nfc]>:
    """

    cleaned = (
        remove_ansi_escape_codes(
            text
        )
        .replace(
            "\r\n",
            "\n"
        )
        .replace(
            "\r",
            "\n"
        )
        .rstrip()
    )

    if not cleaned:
        return False

    last_line = (
        cleaned
        .split(
            "\n"
        )[-1]
        .strip()
    )

    return last_line.lower() in {
        ">:",
        "nfc>:",
        "[nfc]>:",
    }


# --------------------------------------------------
# READ SERIAL OUTPUT UNTIL REAL CLI PROMPT
# --------------------------------------------------

def read_until_prompt(
    connection,
    timeout=5
):
    """
    Read Flipper serial output until the existing CLI prompt
    detector succeeds or the timeout expires.

    Diagnostic output is printed only after the read finishes.
    No timeout, command, or prompt-matching behavior is changed.
    """

    start_time = time.time()
    received = bytearray()
    prompt_detected = False

    while time.time() - start_time < timeout:
        try:
            waiting = connection.in_waiting
            chunk = connection.read(waiting if waiting > 0 else 1)
        except serial.SerialException:
            raise

        if chunk:
            received.extend(chunk)
            decoded = received.decode("utf-8", errors="replace")

            if output_ends_with_prompt(decoded):
                # Allow trailing serial bytes, as in the original code.
                time.sleep(0.03)
                while connection.in_waiting > 0:
                    received.extend(
                        connection.read(connection.in_waiting)
                    )

                final_decoded = received.decode(
                    "utf-8", errors="replace"
                )
                if output_ends_with_prompt(final_decoded):
                    prompt_detected = True
                    break
        else:
            time.sleep(0.005)

    decoded = received.decode("utf-8", errors="replace")
    cleaned_output = remove_ansi_escape_codes(decoded)
    elapsed = time.time() - start_time

    print()
    print("========================================")
    print("FLIPPER CLI RESPONSE DIAGNOSTIC")
    print("========================================")
    print(f"Elapsed Time : {elapsed:.3f} s")
    print(f"Timeout      : {timeout:.3f} s")
    print(f"Bytes Read   : {len(received)}")
    print(f"Prompt Found : {prompt_detected}")
    print(f"Timed Out    : {not prompt_detected}")
    print(f"Output Tail  : {repr(cleaned_output[-200:])}")
    print("========================================")
    print()

    return cleaned_output


# --------------------------------------------------
# SEND CLI COMMAND
# --------------------------------------------------

def send_command(
    connection,
    command,
    timeout=5
):
    """
    Send one command to the Flipper CLI
    and return cleaned textual output.
    """

    connection.reset_input_buffer()

    command_bytes = (
        command
        + "\r"
    ).encode(
        "utf-8"
    )

    connection.write(
        command_bytes
    )

    connection.flush()

    return read_until_prompt(
        connection,
        timeout=timeout
    )


# --------------------------------------------------
# CONNECT TO FLIPPER
# --------------------------------------------------

def connect_to_flipper(
    port
):
    """
    Open and verify the Flipper Zero USB
    serial connection.
    """

    print()

    print(
        "========================================"
    )

    print(
        "CONNECTING TO FLIPPER ZERO"
    )

    print(
        "========================================"
    )

    print(
        "Port :",
        port
    )

    print(
        "Baud :",
        BAUD_RATE
    )

    connection = serial.Serial(
        port=port,
        baudrate=BAUD_RATE,
        timeout=SERIAL_READ_TIMEOUT,
        write_timeout=5
    )

    # Give Windows USB serial time to settle.
    time.sleep(
        1
    )

    connection.reset_input_buffer()
    connection.reset_output_buffer()

    # Wake the main Flipper CLI.
    connection.write(
        b"\r"
    )

    connection.flush()

    time.sleep(
        0.3
    )

    startup_output = (
        read_until_prompt(
            connection,
            timeout=4
        )
    )

    # Harmless command to verify the device.
    info_output = (
        send_command(
            connection,
            "info device",
            timeout=6
        )
    )

    combined_output = (
        startup_output
        + "\n"
        + info_output
    )

    verification_text = (
        combined_output.lower()
    )

    if (
        "flipper" not in verification_text
        and "firmware" not in verification_text
        and "hardware" not in verification_text
    ):

        connection.close()

        raise RuntimeError(
            "The selected serial port did not "
            "respond like a Flipper Zero CLI."
        )

    print(
        "Status : CONNECTED"
    )

    print()

    write_runtime_state(
        status="READY",
        message=(
            "Flipper Zero connected. "
            "Ready for NFC card."
        ),
        port=port,
    )

    return connection


# --------------------------------------------------
# ENTER NFC CLI
# --------------------------------------------------

def enter_nfc_cli(
    connection
):
    """
    Enter the Flipper NFC command-line subsystem.
    """

    output = (
        send_command(
            connection,
            "nfc",
            timeout=8
        )
    )

    normalized_output = (
        output.lower()
    )

    if (
        "nfc command line interface"
        not in normalized_output
        and not output_ends_with_prompt(
            output
        )
    ):

        raise RuntimeError(
            "Could not enter the Flipper NFC CLI."
        )

    cleaned = (
        remove_ansi_escape_codes(
            output
        )
        .replace(
            "\r\n",
            "\n"
        )
        .replace(
            "\r",
            "\n"
        )
        .rstrip()
    )

    last_line = (
        cleaned
        .split(
            "\n"
        )[-1]
        .strip()
        .lower()
        if cleaned
        else ""
    )

    if (
        last_line not in ("nfc>:", "[nfc]>:")
        and (
            "nfc command line interface"
            not in normalized_output
        )
    ):

        raise RuntimeError(
            "Flipper responded, but NFC CLI "
            "was not confirmed."
        )

    print(
        "NFC CLI : READY"
    )

    return output


# --------------------------------------------------
# EXIT NFC CLI
# --------------------------------------------------

def exit_nfc_cli(
    connection
):
    """
    Exit the NFC subsystem and return
    to the main Flipper CLI.
    """

    output = (
        send_command(
            connection,
            "exit",
            timeout=6
        )
    )

    return output


# --------------------------------------------------
# BUILD UNIQUE FLIPPER FILE PATH
# --------------------------------------------------

def build_remote_nfc_path():
    """
    Create a unique NFC filename on the
    Flipper microSD card.
    """

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S_%f"
        )
    )

    filename = (
        f"N3_USB_SCAN_{timestamp}.nfc"
    )

    remote_path = (
        f"/ext/nfc/{filename}"
    )

    return (
        filename,
        remote_path
    )


# --------------------------------------------------
# TRIGGER PHYSICAL NFC SCAN
# --------------------------------------------------

def trigger_nfc_scan(
    connection,
    remote_path,
    timeout_ms
):
    """
    Ask the Flipper NFC subsystem to read a physical card.

    Measure the NFC CLI entry, dump command, and CLI exit
    separately without changing the existing scan commands
    or their timeouts.
    """

    enter_start = time.perf_counter()
    enter_nfc_cli(
        connection
    )
    enter_duration = time.perf_counter() - enter_start

    print()
    print("Waiting for NFC card...")
    print("Place the card on the Flipper NFC area.")
    print()

    write_runtime_state(
        status="SCANNING",
        message=(
            "Scanning NFC card. "
            "Keep the card on the Flipper reader."
        ),
        remote_file=remote_path,
    )

    command = (
        f"dump -f {remote_path} "
        f"-t {timeout_ms}"
    )

    command_timeout = (
        timeout_ms / 1000
        + 15
    )

    dump_start = time.perf_counter()
    output = send_command(
        connection,
        command,
        timeout=command_timeout
    )
    dump_duration = time.perf_counter() - dump_start

    print("NFC scan command completed.")

    exit_start = time.perf_counter()
    exit_nfc_cli(
        connection
    )
    exit_duration = time.perf_counter() - exit_start

    print()
    print("========================================")
    print("N3 NFC CLI PERFORMANCE")
    print("========================================")
    print(f"Enter NFC CLI : {enter_duration:.3f} s")
    print(f"NFC Dump      : {dump_duration:.3f} s")
    print(f"Exit NFC CLI  : {exit_duration:.3f} s")
    print("========================================")
    print()

    return output


# --------------------------------------------------
# READ REMOTE NFC FILE
# --------------------------------------------------

def read_remote_nfc_file(
    connection,
    remote_path
):
    """
    Retrieve the generated Flipper .nfc file
    through the USB CLI.
    """

    command = (
        f"storage read {remote_path}"
    )

    return send_command(
        connection,
        command,
        timeout=5
    )


# --------------------------------------------------
# EXTRACT PURE .NFC CONTENT
# --------------------------------------------------

def extract_nfc_content(
    cli_output
):
    """
    Extract the actual .nfc file body from
    storage read output.
    """

    cleaned = (
        remove_ansi_escape_codes(
            cli_output
        )
        .replace(
            "\r\n",
            "\n"
        )
        .replace(
            "\r",
            "\n"
        )
    )

    marker = (
        "Filetype: Flipper NFC device"
    )

    marker_position = (
        cleaned.find(
            marker
        )
    )

    if marker_position == -1:

        return None

    content = cleaned[
        marker_position:
    ]

    lines = content.split(
        "\n"
    )

    output_lines = []

    for line in lines:

        stripped = (
            line.strip()
        )

        if (
            stripped == ">:"
            or stripped.lower()
            == "nfc>:"
        ):

            break

        output_lines.append(
            line.rstrip()
        )

    while (
        output_lines
        and not output_lines[-1]
    ):

        output_lines.pop()

    if not output_lines:

        return None

    return (
        "\n".join(
            output_lines
        )
        + "\n"
    )


# --------------------------------------------------
# VALIDATE FLIPPER NFC CONTENT
# --------------------------------------------------

def validate_nfc_content(
    content
):
    """
    Confirm that retrieved text is a valid-looking
    Flipper NFC dump before sending it to N3.
    """

    if not content:

        return False

    required_markers = [
        "Filetype: Flipper NFC device",
        "Version:",
        "Device type:",
        "UID:",
    ]

    return all(
        marker in content
        for marker in required_markers
    )


# --------------------------------------------------
# BUILD CONTENT HASH
# --------------------------------------------------

def calculate_content_hash(
    content
):
    """
    Calculate SHA-256 fingerprint of the
    acquired NFC dump.
    """

    return hashlib.sha256(
        content.encode(
            "utf-8"
        )
    ).hexdigest()


# --------------------------------------------------
# SAVE INTO N3 INCOMING DIRECTORY
# --------------------------------------------------

def save_to_n3_incoming(
    filename,
    content
):
    """
    Atomically place a complete acquired NFC dump
    into the N3 incoming directory.
    """

    INCOMING_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    final_path = (
        INCOMING_DIR
        / filename
    )

    temporary_path = (
        INCOMING_DIR
        / (
            filename
            + ".tmp"
        )
    )

    temporary_path.write_text(
        content,
        encoding="utf-8"
    )

    temporary_path.replace(
        final_path
    )

    return final_path


# --------------------------------------------------
# PERFORM ONE COMPLETE USB ACQUISITION
# --------------------------------------------------

def acquire_one_scan(
    connection,
    timeout_ms
):
    """
    Complete one end-to-end acquisition.

    Physical NFC card
        ->
    Flipper Zero
        ->
    USB CLI
        ->
    Flipper .nfc dump
        ->
    PC
        ->
    data/incoming
    """

    acquisition_start = time.perf_counter()

    (
        filename,
        remote_path
    ) = build_remote_nfc_path()

    print()

    print(
        "========================================"
    )

    print(
        "N3 USB NFC ACQUISITION"
    )

    print(
        "========================================"
    )

    print(
        "Remote File :",
        remote_path
    )

    print()

    scan_start = time.perf_counter()

    scan_output = (
        trigger_nfc_scan(
            connection,
            remote_path,
            timeout_ms
        )
    )

    scan_duration = time.perf_counter() - scan_start
    print(f"[PERFORMANCE] NFC Scan: {scan_duration:.3f} s")

    # STEP 45 - CHECK NFC DUMP RESULT
    # Retrieve the file only after confirmed dump success.

    expected_confirmation = (
        f"Dump saved to '{remote_path}'"
    )

    if expected_confirmation not in scan_output:

        if re.search(
            r"(?im)^\s*Error:\s*timeout\s*$",
            scan_output
        ):
            dump_result = "NO_CARD_TIMEOUT"
            message = "No NFC card detected. Ready for next scan."
        else:
            dump_result = "READ_FAILED"
            message = "NFC read failed. Present the card again."

        print(f"NFC Dump Result : {dump_result}")
        print("Storage Read    : SKIPPED (no saved NFC dump confirmed)")

        write_runtime_state(
            status="READY",
            message=message,
            remote_file=remote_path,
        )

        return None

    print("NFC Dump Result : SUCCESS")


    # --------------------------------------------------
    # RETRIEVE CREATED FLIPPER DUMP
    # --------------------------------------------------

    retrieval_start = time.perf_counter()

    read_output = (
        read_remote_nfc_file(
            connection,
            remote_path
        )
    )

    retrieval_duration = time.perf_counter() - retrieval_start
    print(f"[PERFORMANCE] USB Retrieval: {retrieval_duration:.3f} s")

    content = (
        extract_nfc_content(
            read_output
        )
    )


    # --------------------------------------------------
    # VALIDATE
    # --------------------------------------------------

    if not validate_nfc_content(
        content
    ):

        print()

        print(
            "Result : NO COMPLETE NFC DUMP"
        )

        print(
            "Reason : The card was not read "
            "successfully, or the resulting "
            "Flipper NFC file could not be "
            "retrieved."
        )

        print()

        write_runtime_state(
            status="ERROR",
            message=(
                "No complete NFC dump was acquired. "
                "Please try the card again."
            ),
            remote_file=remote_path,
        )

        total_duration = time.perf_counter() - acquisition_start
        print(f"[PERFORMANCE] Total failed acquisition: {total_duration:.3f} s")

        return None


    # --------------------------------------------------
    # HASH ACQUIRED CONTENT
    # --------------------------------------------------

    content_hash = (
        calculate_content_hash(
            content
        )
    )


    # --------------------------------------------------
    # FORWARD INTO N3 PIPELINE
    # --------------------------------------------------

    local_path = (
        save_to_n3_incoming(
            filename,
            content
        )
    )

    write_runtime_state(
        status="VERIFYING",
        message=(
            "NFC acquisition completed. "
            "N3 integrity verification is running."
        ),
        source_file=local_path.name,
        remote_file=remote_path,
    )

    print()

    print(
        "========================================"
    )

    print(
        "ACQUISITION SUCCESS"
    )

    print(
        "========================================"
    )

    print(
        "Remote File :",
        remote_path
    )

    print(
        "N3 Input    :",
        local_path
    )

    print(
        "SHA-256     :",
        content_hash
    )

    print(
        "Status      : READY_FOR_N3"
    )

    print()

    total_acquisition_time = time.perf_counter() - acquisition_start

    print()
    print("========================================")
    print("N3 ACQUISITION PERFORMANCE")
    print("========================================")
    print(f"NFC Scan       : {scan_duration:.3f} s")
    print(f"USB Retrieval  : {retrieval_duration:.3f} s")
    print(f"Other overhead : {total_acquisition_time - scan_duration - retrieval_duration:.3f} s")
    print(f"Total          : {total_acquisition_time:.3f} s")
    print("========================================")
    print()

    return {
        "local_path":
            local_path,

        "remote_path":
            remote_path,

        "content_hash":
            content_hash,

        "scan_output":
            scan_output,
    }


# --------------------------------------------------
# CONTINUOUS ACQUISITION MODE
# --------------------------------------------------

def run_continuous_mode(
    connection,
    timeout_ms,
    cooldown
):
    """
    Continuously perform NFC acquisition attempts.

    The user can stop the adapter using Ctrl+C.
    """

    print()

    print(
        "========================================"
    )

    print(
        "CONTINUOUS MODE ACTIVE"
    )

    print(
        "========================================"
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    write_runtime_state(
        status="READY",
        message=(
            "Flipper Zero connected. "
            "Ready for NFC card."
        ),
    )

    last_hash = None
    last_hash_time = 0

    while True:

        result = (
            acquire_one_scan(
                connection,
                timeout_ms
            )
        )

        if result is None:

            # After a failed acquisition give the user
            # time to reposition/remove the card.
            time.sleep(
                1
            )

            write_runtime_state(
                status="READY",
                message=(
                    "Ready to try again. "
                    "Present an NFC card."
                ),
            )

            continue

        current_hash = (
            result[
                "content_hash"
            ]
        )

        current_time = (
            time.time()
        )

        if (
            current_hash == last_hash
            and (
                current_time
                - last_hash_time
            ) < cooldown
        ):

            print(
                "Notice : Same NFC state was "
                "observed again within the "
                "cooldown window."
            )

        last_hash = (
            current_hash
        )

        last_hash_time = (
            current_time
        )

        # Keep VERIFYING active while N3 finishes processing.
        # The dashboard detects the newly generated report and
        # temporarily renders RESULT — VALID / MODIFIED / UNKNOWN.
        time.sleep(
            cooldown
        )

        # After the result has remained visible for the cooldown
        # period, return the live banner to READY.
        write_runtime_state(
            status="READY",
            message=(
                "Verification cycle completed. "
                "Remove the current card and present "
                "the next NFC card."
            ),
        )


# --------------------------------------------------
# COMMAND LINE ENTRY
# --------------------------------------------------

def main():

    argument_parser = (
        argparse.ArgumentParser(
            description=(
                "N3 direct Flipper Zero USB "
                "NFC acquisition adapter."
            )
        )
    )

    argument_parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        help=(
            "Flipper Zero serial port. "
            "Example: COM9"
        ),
    )

    argument_parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT_MS,
        help=(
            "NFC scan timeout in milliseconds."
        ),
    )

    argument_parser.add_argument(
        "--continuous",
        action="store_true",
        help=(
            "Continuously perform NFC acquisitions."
        ),
    )

    argument_parser.add_argument(
        "--cooldown",
        type=float,
        default=POST_SCAN_COOLDOWN,
        help=(
            "Delay between continuous "
            "scan attempts."
        ),
    )

    args = (
        argument_parser.parse_args()
    )

    connection = None

    try:

        connection = (
            connect_to_flipper(
                args.port
            )
        )

        if args.continuous:

            run_continuous_mode(
                connection,
                args.timeout,
                args.cooldown
            )

        else:

            acquire_one_scan(
                connection,
                args.timeout
            )

    except KeyboardInterrupt:

        print()

        print(
            "N3 Flipper USB adapter stopped."
        )

    except (
        serial.SerialException,
        RuntimeError,
        OSError
    ) as error:

        print()

        print(
            "========================================"
        )

        print(
            "FLIPPER USB ERROR"
        )

        print(
            "========================================"
        )

        print(
            error
        )

        print()

        try:

            write_runtime_state(
                status="ERROR",
                message=(
                    "Flipper USB acquisition error: "
                    f"{error}"
                ),
            )

        except OSError:

            pass

    finally:

        if (
            connection is not None
            and connection.is_open
        ):

            connection.close()


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == "__main__":

    main()
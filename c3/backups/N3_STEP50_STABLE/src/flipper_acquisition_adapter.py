from pathlib import Path

import argparse
import json
import shutil
import time
from datetime import datetime


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

INCOMING_DIR = (
    PROJECT_ROOT
    / "data"
    / "incoming"
)

DEFAULT_FLIPPER_DROP_DIR = (
    PROJECT_ROOT
    / "data"
    / "flipper_drop"
)

STATE_FILE = (
    PROJECT_ROOT
    / "data"
    / ".flipper_acquisition_state.json"
)

CHECK_INTERVAL = 1


# --------------------------------------------------
# LOAD ADAPTER STATE
# --------------------------------------------------

def load_state():
    """
    Load previously observed Flipper NFC files.

    This prevents the same unchanged file from being
    imported repeatedly after adapter restart.
    """

    if not STATE_FILE.exists():
        return {}

    try:

        with STATE_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )

        if isinstance(
            data,
            dict
        ):
            return data

    except (
        OSError,
        json.JSONDecodeError
    ):
        pass

    return {}


# --------------------------------------------------
# SAVE ADAPTER STATE
# --------------------------------------------------

def save_state(state):
    """
    Persist observed file signatures.
    """

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_path = (
        STATE_FILE.with_suffix(
            ".tmp"
        )
    )

    with temporary_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            state,
            file,
            indent=4
        )

    temporary_path.replace(
        STATE_FILE
    )


# --------------------------------------------------
# BUILD FILE SIGNATURE
# --------------------------------------------------

def build_file_signature(file_path):
    """
    Build a lightweight signature using:

    - file size
    - modification time

    If the Flipper/qFlipper rewrites an NFC file
    using the same filename, the changed signature
    allows N3 to import it again.
    """

    stat = file_path.stat()

    return {
        "size":
            stat.st_size,

        "modified_ns":
            stat.st_mtime_ns,
    }


# --------------------------------------------------
# CHECK WHETHER FILE IS READY
# --------------------------------------------------

def wait_until_file_ready(
    file_path,
    timeout=15
):
    """
    Wait until a source .nfc file has finished
    being written before copying it.
    """

    start_time = time.time()

    previous_size = -1
    stable_count = 0


    while (
        time.time() - start_time
        < timeout
    ):

        try:

            current_size = (
                file_path.stat().st_size
            )

            with file_path.open(
                "rb"
            ) as file:

                file.read(1)


            if (
                current_size
                == previous_size
                and current_size > 0
            ):

                stable_count += 1

                if stable_count >= 2:
                    return True

            else:

                stable_count = 0

                previous_size = (
                    current_size
                )

        except (
            PermissionError,
            OSError
        ):

            stable_count = 0


        time.sleep(0.5)


    return False


# --------------------------------------------------
# BUILD UNIQUE DESTINATION NAME
# --------------------------------------------------

def build_destination_path(
    source_path
):
    """
    Create a unique incoming filename.

    Example:

    NTAG215-001_ENROLLMENT.nfc

    becomes:

    NTAG215-001_ENROLLMENT_20261005_030102.nfc
    """

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S_%f"
        )
    )

    destination_name = (
        f"{source_path.stem}_"
        f"{timestamp}"
        f"{source_path.suffix}"
    )

    return (
        INCOMING_DIR
        / destination_name
    )


# --------------------------------------------------
# IMPORT ONE NFC FILE
# --------------------------------------------------

def import_nfc_file(
    source_path
):
    """
    Copy one completed NFC acquisition into
    the common N3 incoming directory.
    """

    if not wait_until_file_ready(
        source_path
    ):

        print(
            "[SKIP] File is not ready:",
            source_path.name
        )

        return None


    INCOMING_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    destination_path = (
        build_destination_path(
            source_path
        )
    )


    shutil.copy2(
        source_path,
        destination_path
    )


    print()
    print(
        "========================================"
    )
    print(
        "FLIPPER ACQUISITION IMPORTED"
    )
    print(
        "========================================"
    )

    print(
        "Source :",
        source_path
    )

    print(
        "N3 Input:",
        destination_path
    )

    print(
        "Status : READY_FOR_N3"
    )

    print()


    return destination_path


# --------------------------------------------------
# SCAN SOURCE DIRECTORY
# --------------------------------------------------

def scan_source_directory(
    source_dir,
    state
):
    """
    Detect new or changed .nfc files.
    """

    if not source_dir.exists():
        return


    source_files = sorted(
        source_dir.glob(
            "*.nfc"
        )
    )


    for source_path in source_files:

        try:

            current_signature = (
                build_file_signature(
                    source_path
                )
            )

        except OSError:
            continue


        state_key = str(
            source_path.resolve()
        )


        previous_signature = (
            state.get(
                state_key
            )
        )


        # File has not changed since
        # previous successful import.
        if (
            previous_signature
            == current_signature
        ):
            continue


        destination = (
            import_nfc_file(
                source_path
            )
        )


        if destination is None:
            continue


        # Recalculate after successful copy
        # in case write metadata changed.
        try:

            state[
                state_key
            ] = (
                build_file_signature(
                    source_path
                )
            )

        except OSError:

            state[
                state_key
            ] = (
                current_signature
            )


        save_state(
            state
        )


# --------------------------------------------------
# RUN ACQUISITION WATCHER
# --------------------------------------------------

def run_adapter(
    source_dir
):
    """
    Continuously watch a Flipper export/sync
    directory and forward new NFC acquisitions
    into the common N3 input pipeline.
    """

    source_dir = (
        source_dir.resolve()
    )


    source_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    INCOMING_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    state = load_state()


    print()
    print(
        "========================================"
    )
    print(
        "N3 FLIPPER ACQUISITION ADAPTER"
    )
    print(
        "========================================"
    )

    print(
        "Source Folder :",
        source_dir
    )

    print(
        "N3 Incoming   :",
        INCOMING_DIR
    )

    print(
        "Check Interval:",
        f"{CHECK_INTERVAL} second"
    )

    print()
    print(
        "Waiting for Flipper NFC acquisitions..."
    )
    print()


    try:

        while True:

            scan_source_directory(
                source_dir,
                state
            )

            time.sleep(
                CHECK_INTERVAL
            )

    except KeyboardInterrupt:

        print()
        print(
            "Flipper acquisition adapter stopped."
        )


# --------------------------------------------------
# COMMAND LINE ENTRY
# --------------------------------------------------

def main():

    argument_parser = (
        argparse.ArgumentParser(
            description=(
                "N3 Flipper NFC acquisition adapter"
            )
        )
    )


    argument_parser.add_argument(
        "--source",
        default=str(
            DEFAULT_FLIPPER_DROP_DIR
        ),
        help=(
            "Folder containing Flipper/qFlipper "
            "NFC dump files."
        ),
    )


    args = (
        argument_parser.parse_args()
    )


    source_dir = Path(
        args.source
    )


    run_adapter(
        source_dir
    )


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == "__main__":
    main()
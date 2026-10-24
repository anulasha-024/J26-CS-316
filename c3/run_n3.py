from pathlib import Path

import argparse
import subprocess
import sys
import time
import webbrowser


# --------------------------------------------------
# N3 PROJECT PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

SCAN_WATCHER = (
    PROJECT_ROOT
    / "src"
    / "scan_watcher.py"
)

FLIPPER_USB_ADAPTER = (
    PROJECT_ROOT
    / "src"
    / "flipper_usb_adapter.py"
)

DASHBOARD_APP = (
    PROJECT_ROOT
    / "dashboard"
    / "app.py"
)


# --------------------------------------------------
# DASHBOARD CONFIGURATION
# --------------------------------------------------

DASHBOARD_URL = (
    "http://127.0.0.1:5000"
)


# --------------------------------------------------
# VERIFY REQUIRED FILES
# --------------------------------------------------

def validate_project_files():
    """
    Confirm all required N3 components exist
    before starting the complete system.
    """

    required_files = [
        SCAN_WATCHER,
        FLIPPER_USB_ADAPTER,
        DASHBOARD_APP,
    ]


    missing_files = [
        file_path
        for file_path in required_files
        if not file_path.exists()
    ]


    if missing_files:

        print()
        print(
            "========================================"
        )
        print(
            "N3 STARTUP ERROR"
        )
        print(
            "========================================"
        )

        print(
            "Required project files are missing:"
        )

        for file_path in missing_files:

            print(
                "-",
                file_path
            )

        print()

        return False


    return True


# --------------------------------------------------
# START CHILD PROCESS
# --------------------------------------------------

def start_process(
    name,
    command
):
    """
    Start one N3 subsystem.
    """

    print(
        f"[START] {name}"
    )

    print(
        "        ",
        " ".join(
            str(item)
            for item in command
        )
    )


    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
    )


    return process


# --------------------------------------------------
# STOP CHILD PROCESS
# --------------------------------------------------

def stop_process(
    name,
    process
):
    """
    Gracefully terminate one N3 subsystem.
    """

    if process is None:

        return


    if process.poll() is not None:

        return


    print(
        f"[STOP] {name}"
    )


    process.terminate()


    try:

        process.wait(
            timeout=5
        )

    except subprocess.TimeoutExpired:

        process.kill()

        process.wait()


# --------------------------------------------------
# MAIN N3 LAUNCHER
# --------------------------------------------------

def main():

    argument_parser = (
        argparse.ArgumentParser(
            description=(
                "Start the complete N3 NFC "
                "integrity verification system."
            )
        )
    )


    argument_parser.add_argument(
        "--port",
        default="COM9",
        help=(
            "Flipper Zero serial port. "
            "Example: COM9"
        ),
    )


    argument_parser.add_argument(
        "--no-browser",
        action="store_true",
        help=(
            "Do not automatically open "
            "the dashboard browser."
        ),
    )


    args = (
        argument_parser.parse_args()
    )


    # --------------------------------------------------
    # PROJECT VALIDATION
    # --------------------------------------------------

    if not validate_project_files():

        sys.exit(
            1
        )


    scan_watcher_process = None

    dashboard_process = None

    flipper_process = None


    print()
    print(
        "========================================"
    )
    print(
        "N3_TIVE SYSTEM LAUNCHER"
    )
    print(
        "========================================"
    )

    print(
        "Project Root :",
        PROJECT_ROOT
    )

    print(
        "Flipper Port :",
        args.port
    )

    print(
        "Dashboard    :",
        DASHBOARD_URL
    )

    print()


    try:

        # --------------------------------------------------
        # START N3 VERIFICATION ENGINE
        # --------------------------------------------------

        scan_watcher_process = (
            start_process(
                "N3 VERIFY WATCHER",
                [
                    sys.executable,
                    str(
                        SCAN_WATCHER
                    ),
                    "VERIFY",
                ]
            )
        )


        time.sleep(
            1
        )


        # --------------------------------------------------
        # START DASHBOARD SERVER
        # --------------------------------------------------

        dashboard_process = (
            start_process(
                "N3 DASHBOARD",
                [
                    sys.executable,
                    str(
                        DASHBOARD_APP
                    ),
                ]
            )
        )


        time.sleep(
            2
        )


        # --------------------------------------------------
        # START FLIPPER USB ACQUISITION
        # --------------------------------------------------

        flipper_process = (
            start_process(
                "FLIPPER USB ADAPTER",
                [
                    sys.executable,
                    str(
                        FLIPPER_USB_ADAPTER
                    ),
                    "--port",
                    args.port,
                    "--continuous",
                ]
            )
        )


        # --------------------------------------------------
        # OPEN DASHBOARD
        # --------------------------------------------------

        if not args.no_browser:

            time.sleep(
                1
            )

            webbrowser.open(
                DASHBOARD_URL
            )


        print()
        print(
            "========================================"
        )
        print(
            "N3 SYSTEM RUNNING"
        )
        print(
            "========================================"
        )

        print()
        print(
            "Physical NFC Card"
        )

        print(
            "      ↓"
        )

        print(
            "Flipper Zero"
        )

        print(
            "      ↓ USB"
        )

        print(
            "N3 Acquisition"
        )

        print(
            "      ↓"
        )

        print(
            "Verification"
        )

        print(
            "      ↓"
        )

        print(
            "Dashboard"
        )

        print()

        print(
            "Dashboard:",
            DASHBOARD_URL
        )

        print()

        print(
            "Press Ctrl+C to stop "
            "the complete N3 system."
        )

        print()


        # --------------------------------------------------
        # SYSTEM HEALTH LOOP
        # --------------------------------------------------

        while True:

            components = [
                (
                    "VERIFY WATCHER",
                    scan_watcher_process
                ),
                (
                    "DASHBOARD",
                    dashboard_process
                ),
                (
                    "FLIPPER USB",
                    flipper_process
                ),
            ]


            for (
                component_name,
                process
            ) in components:

                if (
                    process is not None
                    and process.poll()
                    is not None
                ):

                    raise RuntimeError(
                        f"{component_name} stopped "
                        f"unexpectedly with exit "
                        f"code {process.returncode}."
                    )


            time.sleep(
                1
            )


    except KeyboardInterrupt:

        print()
        print(
            "Stopping N3 system..."
        )


    except RuntimeError as error:

        print()
        print(
            "========================================"
        )
        print(
            "N3 RUNTIME ERROR"
        )
        print(
            "========================================"
        )

        print(
            error
        )

        print()


    finally:

        # Stop acquisition first so no new
        # scans arrive during shutdown.
        stop_process(
            "FLIPPER USB ADAPTER",
            flipper_process
        )

        stop_process(
            "VERIFY WATCHER",
            scan_watcher_process
        )

        stop_process(
            "DASHBOARD",
            dashboard_process
        )


        print()
        print(
            "========================================"
        )
        print(
            "N3 SYSTEM STOPPED"
        )
        print(
            "========================================"
        )

        print()


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == "__main__":
    main()
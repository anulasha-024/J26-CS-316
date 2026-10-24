from pathlib import Path
import subprocess
import sys
import threading
import time
import signal

PROJECT_ROOT = Path(__file__).resolve().parent
DASHBOARD = PROJECT_ROOT / "python" / "dashboard.py"
SCANNER = PROJECT_ROOT / "python" / "live_card_scanner.py"

SCAN_INTERVAL_SECONDS = 5


def stream_output(proc):
    """Show scanner output in this terminal."""
    try:
        for line in iter(proc.stdout.readline, ""):
            if not line:
                break
            print(line, end="", flush=True)
    except Exception:
        pass


def auto_press_enter(proc):
    """
    Automatically trigger the existing scanner.
    The scanner currently waits for ENTER before each scan.
    """
    time.sleep(2)

    while proc.poll() is None:
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            break

        time.sleep(SCAN_INTERVAL_SECONDS)


def main():
    if not DASHBOARD.exists():
        print(f"[ERROR] dashboard.py not found:\n{DASHBOARD}")
        input("Press Enter to exit...")
        return

    if not SCANNER.exists():
        print(f"[ERROR] live_card_scanner.py not found:\n{SCANNER}")
        input("Press Enter to exit...")
        return

    print("=" * 60)
    print("N1 NFC SECURITY SYSTEM")
    print("=" * 60)
    print("Starting dashboard...")
    print("Starting automatic NFC scanner...")
    print("No manual ENTER is required.")
    print("Place a lab NFC card on the Flipper Zero.")
    print("Press Ctrl+C here to stop everything.")
    print("=" * 60)

    dashboard_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(DASHBOARD),
            "--server.headless=false",
        ],
        cwd=str(PROJECT_ROOT),
    )

    # Give Streamlit a moment to start and open the browser.
    time.sleep(2)

    scanner_proc = subprocess.Popen(
        [
            sys.executable,
            "-u",
            str(SCANNER),
        ],
        cwd=str(PROJECT_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    output_thread = threading.Thread(
        target=stream_output,
        args=(scanner_proc,),
        daemon=True,
    )
    output_thread.start()

    enter_thread = threading.Thread(
        target=auto_press_enter,
        args=(scanner_proc,),
        daemon=True,
    )
    enter_thread.start()

    try:
        while True:
            if dashboard_proc.poll() is not None:
                print("\nDashboard process stopped.")
                break

            if scanner_proc.poll() is not None:
                print("\nScanner process stopped.")
                break

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping N1 system...")

    finally:
        for proc in (scanner_proc, dashboard_proc):
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass

        time.sleep(1)

        for proc in (scanner_proc, dashboard_proc):
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

        print("N1 system stopped.")


if __name__ == "__main__":
    main()

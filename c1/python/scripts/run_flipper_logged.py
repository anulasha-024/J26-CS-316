from datetime import datetime
from pathlib import Path
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent

EXPERIMENT_SCRIPT = SCRIPT_DIR / "flipper_auto_timing.py"

LOG_DIR = (
    PROJECT_ROOT
    / "results"
    / "Reports"
    / "Auto_Experiment_Logs"
)

LOG_DIR.mkdir(parents=True, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
log_file = LOG_DIR / f"N1_Experiment_{timestamp}.log"


def emit(message, file):
    print(message, end="", flush=True)
    file.write(message)
    file.flush()


def main():
    exit_code = 1

    with open(log_file, "w", encoding="utf-8") as log:

        emit("N1 AUTOMATED EXPERIMENT LOG\n", log)
        emit("=" * 45 + "\n", log)

        emit(
            f"Started: {datetime.now().astimezone().isoformat()}\n",
            log
        )

        emit(f"Script: {EXPERIMENT_SCRIPT.name}\n", log)
        emit(f"Log File: {log_file}\n\n", log)

        process = subprocess.Popen(
            [sys.executable, "-u", str(EXPERIMENT_SCRIPT)],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1
        )

        try:
            for line in process.stdout:
                emit(line, log)

            exit_code = process.wait()

        except KeyboardInterrupt:
            emit("\nEXPERIMENT INTERRUPTED BY USER\n", log)
            process.terminate()
            process.wait()
            exit_code = 130

        finally:
            process.stdout.close()

        emit(
            f"\nFinished: {datetime.now().astimezone().isoformat()}\n",
            log
        )

        emit(f"Exit Code: {exit_code}\n", log)
        emit("=" * 45 + "\n", log)

    print(f"\nEvidence saved: {log_file}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

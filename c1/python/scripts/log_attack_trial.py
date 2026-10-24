from pathlib import Path
from datetime import datetime
import csv


# --------------------------------------------------
# Project paths
# --------------------------------------------------

project_root = Path(__file__).resolve().parents[2]

dataset_folder = project_root / "Datasets"
attacks_file = dataset_folder / "attacks.csv"

dataset_folder.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# CSV columns
# --------------------------------------------------

fields = [
    "config_id",
    "tier",
    "repeat_no",
    "read_success",
    "write_success",
    "emulation_success",
    "compromised",
    "time_to_compromise",
    "censored",
    "attempts",
    "tool_version",
    "timestamp",
    "notes",
]


# --------------------------------------------------
# Create attacks.csv if missing
# --------------------------------------------------

if not attacks_file.exists():
    with open(attacks_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()


# --------------------------------------------------
# Binary input helper
#
# 1     = Yes / Success
# 0     = No / Failed
# Enter = Not tested / Unknown
# --------------------------------------------------

def get_binary(prompt):
    while True:
        value = input(
            f"{prompt} (1=Yes, 0=No, Enter=Not tested): "
        ).strip()

        if value == "":
            return None

        if value in ["0", "1"]:
            return int(value)

        print(
            "Please enter 0, 1, or press Enter for Not tested."
        )


# --------------------------------------------------
# Start logger
# --------------------------------------------------

print()
print("N1 NFC Attack Trial Logger")
print("--------------------------")


# --------------------------------------------------
# Config ID
# --------------------------------------------------

config_id = input(
    "Config ID [NTAG215_01_BASELINE]: "
).strip()

if config_id == "":
    config_id = "NTAG215_01_BASELINE"


# --------------------------------------------------
# Attacker tier
# --------------------------------------------------

while True:
    tier = input(
        "Tier (T1=Smartphone, T2=Flipper Zero, T3=Proxmark3): "
    ).strip().upper()

    if tier in ["T1", "T2", "T3"]:
        break

    print("Please enter T1, T2, or T3.")


# --------------------------------------------------
# Repeat number
# --------------------------------------------------

while True:
    try:
        repeat_no = int(input("Repeat number: "))

        if repeat_no >= 1:
            break

    except ValueError:
        pass

    print("Please enter a number starting from 1.")


# --------------------------------------------------
# Trial results
# --------------------------------------------------

read_success = get_binary("Read success?")
write_success = get_binary("Write success?")
emulation_success = get_binary("Emulation success?")
compromised = get_binary("Compromised?")


# --------------------------------------------------
# Timing / censoring
#
# compromised = None:
#     timing unknown
#
# compromised = 1:
#     actual time to compromise required
#
# compromised = 0:
#     actual observation duration can be entered
#     Enter = not measured
# --------------------------------------------------

if compromised is None:

    time_to_compromise = None
    censored = None


elif compromised == 1:

    while True:
        raw = input(
            "Actual time to compromise in seconds "
            "(0-1800, decimals allowed): "
        ).strip()

        try:
            measured_time = float(raw)

            if 0 < measured_time <= 1800:
                time_to_compromise = measured_time
                censored = 0
                break

        except ValueError:
            pass

        print(
            "Please enter an actual measured time "
            "between 0 and 1800 seconds."
        )


else:

    while True:
        raw = input(
            "Actual observation duration in seconds "
            "(0-1800, decimals allowed, Enter if not measured): "
        ).strip()

        if raw == "":
            time_to_compromise = None
            censored = None
            break

        try:
            measured_time = float(raw)

            if 0 < measured_time <= 1800:
                time_to_compromise = measured_time
                censored = 1
                break

        except ValueError:
            pass

        print(
            "Please enter an actual measured time "
            "between 0 and 1800 seconds, "
            "or press Enter."
        )


# --------------------------------------------------
# Number of attempts
# --------------------------------------------------

while True:
    try:
        attempts = int(input("Number of attempts: "))

        if attempts >= 1:
            break

    except ValueError:
        pass

    print("Please enter a number starting from 1.")


# --------------------------------------------------
# Tool information
# --------------------------------------------------

tool_version = input(
    "Tool / version: "
).strip()

notes = input(
    "Notes: "
).strip()


# --------------------------------------------------
# Timestamp
# --------------------------------------------------

timestamp = datetime.now().isoformat(
    timespec="seconds"
)


# --------------------------------------------------
# Build trial record
# --------------------------------------------------

trial = {
    "config_id": config_id,
    "tier": tier,
    "repeat_no": repeat_no,
    "read_success": read_success,
    "write_success": write_success,
    "emulation_success": emulation_success,
    "compromised": compromised,
    "time_to_compromise": time_to_compromise,
    "censored": censored,
    "attempts": attempts,
    "tool_version": tool_version,
    "timestamp": timestamp,
    "notes": notes,
}


# --------------------------------------------------
# Save trial
# --------------------------------------------------

with open(
    attacks_file,
    "a",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fields
    )

    writer.writerow(trial)


# --------------------------------------------------
# Final result
# --------------------------------------------------

print()
print("Trial saved successfully.")
print(f"Saved to: {attacks_file}")
print(f"Config ID: {config_id}")
print(f"Tier: {tier}")
print(f"Repeat number: {repeat_no}")
print(f"Read success: {read_success}")
print(f"Write success: {write_success}")
print(f"Emulation success: {emulation_success}")
print(f"Compromised: {compromised}")
print(f"Time to compromise: {time_to_compromise}")
print(f"Censored: {censored}")
print(f"Attempts: {attempts}")
print(f"Tool / version: {tool_version}")
print(f"Timestamp: {timestamp}")
print(f"Notes: {notes}")
import time


# --------------------------------------------------
# START PERFORMANCE TIMER
# --------------------------------------------------

def start_timer():
    """
    Start a high-resolution performance timer.

    This timer is used only for measuring
    N3 processing duration.
    """

    return time.perf_counter()


# --------------------------------------------------
# CALCULATE ELAPSED TIME
# --------------------------------------------------

def calculate_elapsed_ms(start_time):
    """
    Calculate the elapsed processing time
    in milliseconds.
    """

    if start_time is None:

        return None

    end_time = time.perf_counter()

    elapsed_seconds = (
        end_time - start_time
    )

    elapsed_ms = (
        elapsed_seconds * 1000
    )

    return round(
        elapsed_ms,
        3
    )
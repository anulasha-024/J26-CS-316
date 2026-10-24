VALID_MODES = {
    "ENROLL",
    "VERIFY",
    "UPDATE",
}


def normalize_mode(mode):
    """
    Validate and normalize the selected N3 operation mode.
    """

    if mode is None:
        raise ValueError(
            "N3 operation mode is missing."
        )

    normalized_mode = mode.strip().upper()

    if normalized_mode not in VALID_MODES:
        raise ValueError(
            "Invalid N3 mode. "
            "Use ENROLL, VERIFY, or UPDATE."
        )

    return normalized_mode
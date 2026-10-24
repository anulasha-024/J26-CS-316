# --------------------------------------------------
# N3 FAMILY-AWARE CHANGE / TAMPER CLASSIFIER
# --------------------------------------------------


def get_result_card_family(
    raw_memory_result,
    ndef_result,
    security_result
):
    """
    Determine the NFC card family from the
    verification-layer results.

    The family-aware verifier stores card_family
    inside its result dictionaries.
    """

    for result in [
        raw_memory_result,
        ndef_result,
        security_result,
    ]:

        if not isinstance(
            result,
            dict
        ):
            continue

        card_family = result.get(
            "card_family"
        )

        if card_family:
            return card_family


    return None


def classify_change(
    raw_memory_result,
    ndef_result,
    security_result
):
    """
    Classify detected NFC changes into
    N3 family-aware change categories.

    NTAG215 application change:
        APPLICATION_NDEF_CHANGE

    MIFARE Classic 1K application change:
        APPLICATION_DATA_CHANGE

    Both families can also produce:
        SECURITY_STATE_CHANGE
        RAW_MEMORY_CHANGE
    """

    classifications = []


    # --------------------------------------------------
    # CARD FAMILY
    # --------------------------------------------------

    card_family = (
        get_result_card_family(
            raw_memory_result,
            ndef_result,
            security_result
        )
    )


    # --------------------------------------------------
    # APPLICATION LAYER CHANGE
    # --------------------------------------------------

    if (
        ndef_result.get(
            "status"
        )
        == "CHANGED"
    ):

        # ----------------------------------------------
        # NTAG215
        # ----------------------------------------------

        if card_family == "NTAG215":

            classifications.append(
                "APPLICATION_NDEF_CHANGE"
            )


        # ----------------------------------------------
        # MIFARE CLASSIC 1K
        # ----------------------------------------------

        elif (
            card_family
            == "MIFARE_CLASSIC_1K"
        ):

            classifications.append(
                "APPLICATION_DATA_CHANGE"
            )


        # ----------------------------------------------
        # FALLBACK
        # ----------------------------------------------

        else:

            classifications.append(
                "APPLICATION_CHANGE"
            )


    # --------------------------------------------------
    # SECURITY-STATE CHANGE
    # --------------------------------------------------

    if (
        security_result.get(
            "status"
        )
        == "CHANGED"
    ):

        classifications.append(
            "SECURITY_STATE_CHANGE"
        )


    # --------------------------------------------------
    # RAW MEMORY CHANGE
    # --------------------------------------------------

    if (
        raw_memory_result.get(
            "status"
        )
        == "CHANGED"
    ):

        classifications.append(
            "RAW_MEMORY_CHANGE"
        )


    # --------------------------------------------------
    # NO CONFIRMED CHANGE
    # --------------------------------------------------

    if not classifications:

        classifications.append(
            "NO_CONFIRMED_CHANGE"
        )


    return classifications
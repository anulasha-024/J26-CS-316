# --------------------------------------------------
# N3 FINAL DECISION ENGINE
# --------------------------------------------------

def make_final_decision(
    raw_memory_result,
    ndef_result,
    security_result
):
    """
    Combine the three N3 verification layers
    and produce the final integrity verdict.
    """

    layer_results = [
        raw_memory_result,
        ndef_result,
        security_result,
    ]

    layer_statuses = {}

    for result in layer_results:

        layer_name = result.get("layer")
        status = result.get("status")

        layer_statuses[layer_name] = status


    # --------------------------------------------------
    # RULE 1:
    # ANY CONFIRMED CHANGE = MODIFIED
    # --------------------------------------------------

    changed_layers = []

    for result in layer_results:

        if result.get("status") == "CHANGED":

            changed_layers.append(
                result.get("layer")
            )

    if changed_layers:

        return {
            "verdict": "MODIFIED",
            "reason": (
                "One or more verification layers "
                "detected a confirmed change."
            ),
            "changed_layers": changed_layers,
            "layer_statuses": layer_statuses,
        }


    # --------------------------------------------------
    # RULE 2:
    # INSUFFICIENT EVIDENCE = UNKNOWN
    # --------------------------------------------------

    insufficient_layers = []

    for result in layer_results:

        if (
            result.get("status")
            == "INSUFFICIENT_EVIDENCE"
        ):

            insufficient_layers.append(
                result.get("layer")
            )

    if insufficient_layers:

        return {
            "verdict": "UNKNOWN",
            "reason": (
                "There is not enough trusted "
                "evidence to make a complete "
                "integrity decision."
            ),
            "insufficient_layers": (
                insufficient_layers
            ),
            "layer_statuses": layer_statuses,
        }


    # --------------------------------------------------
    # RULE 3:
    # ALL LAYERS MATCH = VALID
    # --------------------------------------------------

    all_match = all(
        result.get("status") == "MATCH"
        for result in layer_results
    )

    if all_match:

        return {
            "verdict": "VALID",
            "reason": (
                "All required verification layers "
                "match the trusted baseline."
            ),
            "changed_layers": [],
            "layer_statuses": layer_statuses,
        }


    # --------------------------------------------------
    # FALLBACK = UNKNOWN
    # --------------------------------------------------

    return {
        "verdict": "UNKNOWN",
        "reason": (
            "The verification results are not "
            "sufficient for a reliable final "
            "decision."
        ),
        "layer_statuses": layer_statuses,
    }


# --------------------------------------------------
# N3 INSUFFICIENT-EVIDENCE DECISION
# --------------------------------------------------

def make_unknown_decision(
    reason,
    insufficient_area
):
    """
    Produce an UNKNOWN verdict when the
    acquisition itself does not contain
    enough complete evidence.
    """

    return {
        "verdict": "UNKNOWN",
        "reason": reason,
        "insufficient_layers": [
            insufficient_area
        ],
        "layer_statuses": {
            insufficient_area:
                "INSUFFICIENT_EVIDENCE"
        },
    }
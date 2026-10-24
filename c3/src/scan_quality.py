# --------------------------------------------------
# SAFE INTEGER CONVERSION
# --------------------------------------------------

def to_int(value):
    """
    Safely convert a value to an integer.
    """

    try:
        return int(value)

    except (TypeError, ValueError):
        return None


# --------------------------------------------------
# NTAG215 QUALITY CHECK
# --------------------------------------------------

def assess_ntag215_quality(
    card_info,
    memory_pages
):
    """
    Check whether an NTAG215 scan contains
    enough complete page evidence.
    """

    reasons = []

    uid = card_info.get("uid")
    card_type = card_info.get("card_type")

    pages_total = to_int(
        card_info.get("pages_total")
    )

    pages_read = to_int(
        card_info.get("pages_read")
    )

    parsed_pages = len(
        memory_pages
    )

    unknown_byte_count = to_int(
        card_info.get(
            "unknown_byte_count"
        )
    )

    if unknown_byte_count is None:
        unknown_byte_count = 0


    # --------------------------------------------------
    # IDENTITY CHECKS
    # --------------------------------------------------

    if not card_type:
        reasons.append(
            "Card type is missing."
        )

    if not uid:
        reasons.append(
            "UID is missing."
        )


    # --------------------------------------------------
    # PAGE COUNT CHECKS
    # --------------------------------------------------

    if pages_total is None:
        reasons.append(
            "Total page count is missing."
        )

    if pages_read is None:
        reasons.append(
            "Read page count is missing."
        )

    if parsed_pages == 0:
        reasons.append(
            "No memory pages were parsed."
        )


    # --------------------------------------------------
    # READER COMPLETENESS CHECK
    # --------------------------------------------------

    if (
        pages_total is not None
        and pages_read is not None
        and pages_read != pages_total
    ):
        reasons.append(
            f"Incomplete read: {pages_read} of "
            f"{pages_total} pages were read."
        )


    # --------------------------------------------------
    # PARSER / READER COUNT CONSISTENCY
    # --------------------------------------------------

    if (
        pages_read is not None
        and parsed_pages != pages_read
    ):
        reasons.append(
            f"Parsed page count ({parsed_pages}) "
            f"does not match reader page count "
            f"({pages_read})."
        )


    # --------------------------------------------------
    # EXPECTED PAGE NUMBER CHECK
    # --------------------------------------------------

    missing_pages = []

    if pages_total is not None:

        expected_pages = set(
            range(pages_total)
        )

        actual_pages = set(
            memory_pages.keys()
        )

        missing_pages = sorted(
            expected_pages
            - actual_pages
        )

        if missing_pages:
            reasons.append(
                "Missing memory pages: "
                + ", ".join(
                    str(page)
                    for page in missing_pages
                )
            )


    # --------------------------------------------------
    # UNKNOWN BYTE CHECK
    # --------------------------------------------------

    if unknown_byte_count > 0:
        reasons.append(
            f"Scan contains "
            f"{unknown_byte_count} unknown byte(s)."
        )


    return {
        "card_family": "NTAG215",
        "card_type": card_type,
        "uid": uid,
        "memory_unit": "PAGE",

        "pages_total": pages_total,
        "pages_read": pages_read,
        "parsed_pages": parsed_pages,
        "missing_pages": missing_pages,

        "blocks_total": None,
        "parsed_blocks": None,
        "missing_blocks": [],

        "unknown_byte_count":
            unknown_byte_count,

        "reasons": reasons,
    }


# --------------------------------------------------
# MIFARE CLASSIC 1K QUALITY CHECK
# --------------------------------------------------

def assess_mifare_classic_1k_quality(
    card_info,
    memory_blocks
):
    """
    Check whether a MIFARE Classic 1K scan
    contains enough complete block evidence.

    Expected structure:

    16 sectors
    64 blocks
    16 bytes per block
    """

    reasons = []

    uid = card_info.get("uid")
    card_type = card_info.get("card_type")

    blocks_total = to_int(
        card_info.get(
            "blocks_total"
        )
    )

    sectors_total = to_int(
        card_info.get(
            "sectors_total"
        )
    )

    parsed_blocks = len(
        memory_blocks
    )

    unknown_byte_count = to_int(
        card_info.get(
            "unknown_byte_count"
        )
    )

    if unknown_byte_count is None:
        unknown_byte_count = 0


    # --------------------------------------------------
    # IDENTITY CHECKS
    # --------------------------------------------------

    if not card_type:
        reasons.append(
            "Card type is missing."
        )

    if not uid:
        reasons.append(
            "UID is missing."
        )


    # --------------------------------------------------
    # EXPECTED MIFARE STRUCTURE
    # --------------------------------------------------

    if blocks_total is None:
        reasons.append(
            "Expected block count is missing."
        )

    elif blocks_total != 64:
        reasons.append(
            f"Unexpected MIFARE Classic 1K "
            f"block count: {blocks_total}. "
            f"Expected 64."
        )


    if sectors_total is None:
        reasons.append(
            "Expected sector count is missing."
        )

    elif sectors_total != 16:
        reasons.append(
            f"Unexpected MIFARE Classic 1K "
            f"sector count: {sectors_total}. "
            f"Expected 16."
        )


    # --------------------------------------------------
    # PARSED BLOCK COUNT
    # --------------------------------------------------

    if parsed_blocks == 0:
        reasons.append(
            "No MIFARE memory blocks were parsed."
        )

    if parsed_blocks != 64:
        reasons.append(
            f"Incomplete MIFARE Classic 1K read: "
            f"{parsed_blocks} of 64 blocks "
            f"were parsed."
        )


    # --------------------------------------------------
    # MISSING BLOCK CHECK
    # --------------------------------------------------

    expected_blocks = set(
        range(64)
    )

    actual_blocks = set(
        memory_blocks.keys()
    )

    missing_blocks = sorted(
        expected_blocks
        - actual_blocks
    )

    if missing_blocks:
        reasons.append(
            "Missing MIFARE blocks: "
            + ", ".join(
                str(block)
                for block in missing_blocks
            )
        )


    # --------------------------------------------------
    # BLOCK SIZE CHECK
    # --------------------------------------------------

    malformed_blocks = []

    for block_number, block_entry in (
        memory_blocks.items()
    ):

        if not isinstance(
            block_entry,
            dict
        ):
            malformed_blocks.append(
                block_number
            )
            continue

        block_data = block_entry.get(
            "data"
        )

        if not block_data:
            malformed_blocks.append(
                block_number
            )
            continue

        byte_values = (
            str(block_data)
            .strip()
            .split()
        )

        # Canonical sector trailers contain
        # masked key bytes (**), but still
        # contain exactly 16 byte positions.
        if len(byte_values) != 16:
            malformed_blocks.append(
                block_number
            )


    malformed_blocks = sorted(
        malformed_blocks
    )

    if malformed_blocks:
        reasons.append(
            "Malformed MIFARE block data: "
            + ", ".join(
                str(block)
                for block in malformed_blocks
            )
        )


    # --------------------------------------------------
    # UNKNOWN BYTE CHECK
    # --------------------------------------------------

    if unknown_byte_count > 0:
        reasons.append(
            f"Scan contains "
            f"{unknown_byte_count} unknown byte(s)."
        )


    return {
        "card_family":
            "MIFARE_CLASSIC_1K",

        "card_type":
            card_type,

        "uid":
            uid,

        "memory_unit":
            "BLOCK",

        "pages_total":
            None,

        "pages_read":
            None,

        "parsed_pages":
            None,

        "missing_pages":
            [],

        "blocks_total":
            blocks_total,

        "sectors_total":
            sectors_total,

        "parsed_blocks":
            parsed_blocks,

        "missing_blocks":
            missing_blocks,

        "malformed_blocks":
            malformed_blocks,

        "unknown_byte_count":
            unknown_byte_count,

        "reasons":
            reasons,
    }


# --------------------------------------------------
# MAIN FAMILY-AWARE QUALITY CHECK
# --------------------------------------------------

def assess_scan_quality(
    canonical_scan
):
    """
    Check whether the NFC scan contains enough
    trustworthy evidence for integrity verification.

    Supported families:

    NTAG215
        -> page-based completeness

    MIFARE Classic 1K
        -> block-based completeness

    If evidence is incomplete, the later N3
    decision should use UNKNOWN instead of
    incorrectly reporting MODIFIED.
    """

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    card_family = card_info.get(
        "card_family"
    )

    memory_pages = canonical_scan.get(
        "memory_pages",
        {}
    )

    memory_blocks = canonical_scan.get(
        "memory_blocks",
        {}
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        quality = (
            assess_ntag215_quality(
                card_info,
                memory_pages
            )
        )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    elif (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        quality = (
            assess_mifare_classic_1k_quality(
                card_info,
                memory_blocks
            )
        )


    # --------------------------------------------------
    # UNSUPPORTED FAMILY
    # --------------------------------------------------

    else:

        quality = {
            "card_family":
                card_family,

            "card_type":
                card_info.get(
                    "card_type"
                ),

            "uid":
                card_info.get(
                    "uid"
                ),

            "memory_unit":
                card_info.get(
                    "memory_unit"
                ),

            "pages_total":
                None,

            "pages_read":
                None,

            "parsed_pages":
                None,

            "missing_pages":
                [],

            "blocks_total":
                None,

            "parsed_blocks":
                None,

            "missing_blocks":
                [],

            "unknown_byte_count":
                card_info.get(
                    "unknown_byte_count"
                ),

            "reasons": [
                (
                    "Unsupported or unknown "
                    "NFC card family."
                )
            ],
        }


    # --------------------------------------------------
    # FINAL QUALITY DECISION
    # --------------------------------------------------

    reasons = quality.get(
        "reasons",
        []
    )

    if len(reasons) == 0:

        quality_status = (
            "COMPLETE"
        )

        is_complete = True

    else:

        quality_status = (
            "INSUFFICIENT_EVIDENCE"
        )

        is_complete = False


    quality[
        "quality_status"
    ] = quality_status

    quality[
        "is_complete"
    ] = is_complete


    return quality
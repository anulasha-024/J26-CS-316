# --------------------------------------------------
# N3 FAMILY-AWARE THREE-LAYER VERIFICATION
# --------------------------------------------------


# ==================================================
# COMMON HELPERS
# ==================================================

def get_card_family(
    canonical_scan,
    baseline
):
    """
    Determine the NFC card family from the
    current scan first, then from baseline.
    """

    current_info = canonical_scan.get(
        "card_info",
        {}
    )

    baseline_info = baseline.get(
        "card_info",
        {}
    )

    family = current_info.get(
        "card_family"
    )

    if not family:
        family = baseline.get(
            "card_family"
        )

    if not family:
        family = baseline_info.get(
            "card_family"
        )

    # Backward compatibility with old NTAG baselines
    if not family:

        current_type = current_info.get(
            "card_type"
        )

        baseline_type = baseline_info.get(
            "card_type"
        )

        if (
            current_type == "NTAG215"
            or baseline_type == "NTAG215"
        ):
            family = "NTAG215"

    return family


def normalize_numeric_keys(
    memory_data
):
    """
    Convert integer/string memory keys into
    one consistent string-key representation.

    Works for:
    - NTAG page numbers
    - MIFARE block numbers
    """

    return {
        str(number): value
        for number, value
        in memory_data.items()
    }


# ==================================================
# NTAG RAW MEMORY VERIFICATION
# ==================================================

def verify_ntag_raw_memory(
    canonical_scan,
    baseline
):
    """
    Compare NTAG215 page memory with
    trusted baseline page memory.
    """

    current_pages = (
        normalize_numeric_keys(
            canonical_scan.get(
                "memory_pages",
                {}
            )
        )
    )

    baseline_pages = (
        normalize_numeric_keys(
            baseline.get(
                "memory_pages",
                {}
            )
        )
    )

    changed_pages = []

    all_pages = (
        set(current_pages.keys())
        |
        set(baseline_pages.keys())
    )

    all_pages = sorted(
        all_pages,
        key=lambda page: int(page)
    )

    for page_number in all_pages:

        old_value = baseline_pages.get(
            page_number
        )

        new_value = current_pages.get(
            page_number
        )

        if old_value != new_value:

            changed_pages.append(
                {
                    "page":
                        int(page_number),

                    "old_value":
                        old_value,

                    "new_value":
                        new_value,
                }
            )

    if changed_pages:
        status = "CHANGED"
    else:
        status = "MATCH"

    return {
        "layer":
            "RAW_MEMORY",

        "card_family":
            "NTAG215",

        "memory_unit":
            "PAGE",

        "status":
            status,

        "changed_page_count":
            len(changed_pages),

        "changed_pages":
            changed_pages,

        # Compatibility fields
        "changed_block_count":
            0,

        "changed_blocks":
            [],
    }


# ==================================================
# MIFARE RAW MEMORY VERIFICATION
# ==================================================

def compare_mifare_block_entries(
    old_entry,
    new_entry
):
    """
    Compare canonical MIFARE block evidence.

    Returns True when the block evidence matches.
    """

    if old_entry is None and new_entry is None:
        return True

    if old_entry is None or new_entry is None:
        return False

    if not isinstance(
        old_entry,
        dict
    ):
        return (
            old_entry == new_entry
        )

    if not isinstance(
        new_entry,
        dict
    ):
        return False

    fields = [
        "sector_number",
        "block_type",
        "data",
    ]

    for field in fields:

        if old_entry.get(
            field
        ) != new_entry.get(
            field
        ):
            return False

    return True


def verify_mifare_raw_memory(
    canonical_scan,
    baseline
):
    """
    Compare MIFARE Classic 1K block memory
    with trusted baseline block memory.

    Localization includes:
    - sector
    - block
    - block type
    - old value
    - new value
    """

    current_blocks = (
        normalize_numeric_keys(
            canonical_scan.get(
                "memory_blocks",
                {}
            )
        )
    )

    baseline_blocks = (
        normalize_numeric_keys(
            baseline.get(
                "memory_blocks",
                {}
            )
        )
    )

    changed_blocks = []

    all_blocks = (
        set(current_blocks.keys())
        |
        set(baseline_blocks.keys())
    )

    all_blocks = sorted(
        all_blocks,
        key=lambda block: int(block)
    )

    for block_number in all_blocks:

        old_entry = baseline_blocks.get(
            block_number
        )

        new_entry = current_blocks.get(
            block_number
        )

        if compare_mifare_block_entries(
            old_entry,
            new_entry
        ):
            continue


        block_number_int = int(
            block_number
        )


        # --------------------------------------------------
        # GET LOCATION INFORMATION
        # --------------------------------------------------

        sector_number = (
            block_number_int // 4
        )

        old_block_type = None
        new_block_type = None

        old_value = None
        new_value = None


        if isinstance(
            old_entry,
            dict
        ):

            sector_number = old_entry.get(
                "sector_number",
                sector_number
            )

            old_block_type = old_entry.get(
                "block_type"
            )

            old_value = old_entry.get(
                "data"
            )


        if isinstance(
            new_entry,
            dict
        ):

            sector_number = new_entry.get(
                "sector_number",
                sector_number
            )

            new_block_type = new_entry.get(
                "block_type"
            )

            new_value = new_entry.get(
                "data"
            )


        block_type = (
            new_block_type
            or old_block_type
        )


        changed_blocks.append(
            {
                "sector_number":
                    sector_number,

                "block":
                    block_number_int,

                "block_number":
                    block_number_int,

                "block_type":
                    block_type,

                "old_value":
                    old_value,

                "new_value":
                    new_value,
            }
        )


    if changed_blocks:
        status = "CHANGED"
    else:
        status = "MATCH"


    return {
        "layer":
            "RAW_MEMORY",

        "card_family":
            "MIFARE_CLASSIC_1K",

        "memory_unit":
            "BLOCK",

        "status":
            status,

        "changed_block_count":
            len(changed_blocks),

        "changed_blocks":
            changed_blocks,

        # Compatibility fields
        "changed_page_count":
            0,

        "changed_pages":
            [],
    }


# ==================================================
# FAMILY-AWARE RAW MEMORY DISPATCHER
# ==================================================

def verify_raw_memory(
    canonical_scan,
    baseline
):
    """
    Verify family-specific raw memory.

    NTAG215
        -> pages

    MIFARE Classic 1K
        -> sectors / blocks
    """

    card_family = get_card_family(
        canonical_scan,
        baseline
    )

    if card_family == "NTAG215":

        return verify_ntag_raw_memory(
            canonical_scan,
            baseline
        )


    if (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        return verify_mifare_raw_memory(
            canonical_scan,
            baseline
        )


    return {
        "layer":
            "RAW_MEMORY",

        "card_family":
            card_family,

        "status":
            "INSUFFICIENT_EVIDENCE",

        "changed_page_count":
            0,

        "changed_pages":
            [],

        "changed_block_count":
            0,

        "changed_blocks":
            [],

        "reason":
            (
                "Raw-memory verification is not "
                "implemented for this NFC family."
            ),
    }


# ==================================================
# NTAG APPLICATION / NDEF VERIFICATION
# ==================================================

def verify_ntag_application(
    canonical_scan,
    baseline
):
    """
    Compare NTAG215 NDEF application evidence.

    Output structure remains compatible with
    the existing NTAG implementation.
    """

    current_ndef = canonical_scan.get(
        "ndef_evidence"
    ) or {}

    baseline_ndef = baseline.get(
        "ndef_evidence"
    ) or {}

    changed_fields = []


    # --------------------------------------------------
    # NDEF PRESENCE
    # --------------------------------------------------

    current_present = current_ndef.get(
        "ndef_present"
    )

    baseline_present = baseline_ndef.get(
        "ndef_present"
    )

    if current_present != baseline_present:

        changed_fields.append(
            {
                "field":
                    "ndef_present",

                "old_value":
                    baseline_present,

                "new_value":
                    current_present,
            }
        )


    # --------------------------------------------------
    # NDEF RECORD
    # --------------------------------------------------

    current_record = current_ndef.get(
        "record"
    ) or {}

    baseline_record = baseline_ndef.get(
        "record"
    ) or {}


    fields_to_check = [
        "record_type",
        "language",
        "encoding",
        "text",
    ]


    for field in fields_to_check:

        old_value = baseline_record.get(
            field
        )

        new_value = current_record.get(
            field
        )

        if old_value != new_value:

            changed_fields.append(
                {
                    "field":
                        field,

                    "old_value":
                        old_value,

                    "new_value":
                        new_value,
                }
            )


    if changed_fields:
        status = "CHANGED"
    else:
        status = "MATCH"


    return {
        "layer":
            "APPLICATION_NDEF",

        "card_family":
            "NTAG215",

        "application_type":
            "NDEF",

        "status":
            status,

        "changed_field_count":
            len(changed_fields),

        "changed_fields":
            changed_fields,
    }


# ==================================================
# MIFARE APPLICATION VERIFICATION
# ==================================================

def verify_mifare_application(
    canonical_scan,
    baseline
):
    """
    Compare controlled MIFARE Classic
    block-based application evidence.

    This evidence is not claimed to be NDEF.
    """

    current_app = canonical_scan.get(
        "ndef_evidence"
    ) or {}

    baseline_app = baseline.get(
        "ndef_evidence"
    ) or {}

    changed_fields = []


    # --------------------------------------------------
    # APPLICATION TYPE
    # --------------------------------------------------

    top_level_fields = [
        "application_evidence_type",
        "application_present",
        "marker_count",
    ]


    for field in top_level_fields:

        old_value = baseline_app.get(
            field
        )

        new_value = current_app.get(
            field
        )

        if old_value != new_value:

            changed_fields.append(
                {
                    "field":
                        field,

                    "old_value":
                        old_value,

                    "new_value":
                        new_value,
                }
            )


    # --------------------------------------------------
    # PRIMARY MARKER
    # --------------------------------------------------

    old_marker = baseline_app.get(
        "primary_marker"
    ) or {}

    new_marker = current_app.get(
        "primary_marker"
    ) or {}


    marker_fields = [
        "sector_number",
        "block_number",
        "block_type",
        "text",
        "block_hex",
    ]


    for field in marker_fields:

        old_value = old_marker.get(
            field
        )

        new_value = new_marker.get(
            field
        )

        if old_value != new_value:

            change = {
                "field":
                    f"primary_marker.{field}",

                "old_value":
                    old_value,

                "new_value":
                    new_value,
            }


            # Add MIFARE localization
            change[
                "sector_number"
            ] = (
                new_marker.get(
                    "sector_number"
                )
                if new_marker
                else old_marker.get(
                    "sector_number"
                )
            )

            change[
                "block_number"
            ] = (
                new_marker.get(
                    "block_number"
                )
                if new_marker
                else old_marker.get(
                    "block_number"
                )
            )


            changed_fields.append(
                change
            )


    if changed_fields:
        status = "CHANGED"
    else:
        status = "MATCH"


    return {
        # Keep the proposal's common
        # Application/NDEF layer name.
        "layer":
            "APPLICATION_NDEF",

        "card_family":
            "MIFARE_CLASSIC_1K",

        "application_type":
            "MIFARE_CLASSIC_DATA_BLOCK_MARKER",

        "status":
            status,

        "changed_field_count":
            len(changed_fields),

        "changed_fields":
            changed_fields,

        "baseline_marker":
            (
                baseline_app.get(
                    "primary_marker"
                )
            ),

        "current_marker":
            (
                current_app.get(
                    "primary_marker"
                )
            ),
    }


# ==================================================
# FAMILY-AWARE APPLICATION DISPATCHER
# ==================================================

def verify_ndef_application(
    canonical_scan,
    baseline
):
    """
    Verify the application layer.

    Function name is preserved for backward
    compatibility.

    NTAG215
        -> NDEF comparison

    MIFARE Classic 1K
        -> block-based application comparison
    """

    card_family = get_card_family(
        canonical_scan,
        baseline
    )


    if card_family == "NTAG215":

        return verify_ntag_application(
            canonical_scan,
            baseline
        )


    if (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        return verify_mifare_application(
            canonical_scan,
            baseline
        )


    return {
        "layer":
            "APPLICATION_NDEF",

        "card_family":
            card_family,

        "status":
            "INSUFFICIENT_EVIDENCE",

        "changed_field_count":
            0,

        "changed_fields":
            [],

        "reason":
            (
                "Application verification is not "
                "implemented for this NFC family."
            ),
    }


# ==================================================
# COMMON SECURITY VALIDATION
# ==================================================

def validate_security_evidence(
    current_security,
    baseline_security
):
    """
    Check whether both current and baseline
    security evidence can be compared.

    Returns None when comparison can continue.
    Otherwise returns an INSUFFICIENT_EVIDENCE
    result.
    """

    if not current_security:

        return {
            "layer":
                "SECURITY_STATE",

            "status":
                "INSUFFICIENT_EVIDENCE",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "Current security-state "
                    "evidence is missing."
                ),
        }


    if not baseline_security:

        return {
            "layer":
                "SECURITY_STATE",

            "status":
                "INSUFFICIENT_EVIDENCE",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "Trusted baseline "
                    "security-state evidence "
                    "is missing."
                ),
        }


    if not current_security.get(
        "supported"
    ):

        return {
            "layer":
                "SECURITY_STATE",

            "status":
                "INSUFFICIENT_EVIDENCE",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "Current card security-state "
                    "is not supported."
                ),
        }


    if not baseline_security.get(
        "supported"
    ):

        return {
            "layer":
                "SECURITY_STATE",

            "status":
                "INSUFFICIENT_EVIDENCE",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "Baseline security-state "
                    "is not supported."
                ),
        }


    if not current_security.get(
        "evidence_complete"
    ):

        return {
            "layer":
                "SECURITY_STATE",

            "status":
                "INSUFFICIENT_EVIDENCE",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "Current security-state "
                    "evidence is incomplete."
                ),
        }


    if not baseline_security.get(
        "evidence_complete"
    ):

        return {
            "layer":
                "SECURITY_STATE",

            "status":
                "INSUFFICIENT_EVIDENCE",

            "changed_field_count":
                0,

            "changed_fields":
                [],

            "reason":
                (
                    "Baseline security-state "
                    "evidence is incomplete."
                ),
        }


    return None


# ==================================================
# NTAG215 SECURITY VERIFICATION
# ==================================================

def verify_ntag_security_state(
    current_security,
    baseline_security
):
    """
    Compare NTAG215 observable security state.
    """

    changed_fields = []


    # --------------------------------------------------
    # LOCK STATE
    # --------------------------------------------------

    top_level_fields = [
        "static_lock_bytes",
        "dynamic_lock_bytes",
    ]


    for field in top_level_fields:

        old_value = baseline_security.get(
            field
        )

        new_value = current_security.get(
            field
        )

        if old_value != new_value:

            changed_fields.append(
                {
                    "field":
                        field,

                    "old_value":
                        old_value,

                    "new_value":
                        new_value,
                }
            )


    # --------------------------------------------------
    # CONFIGURATION
    # --------------------------------------------------

    current_config = current_security.get(
        "configuration",
        {}
    )

    baseline_config = baseline_security.get(
        "configuration",
        {}
    )


    configuration_fields = [
        "auth0_page",
        "password_protection_enabled",
        "protection_mode",
        "configuration_locked",
        "auth_limit",
        "nfc_counter_enabled",
        "nfc_counter_password_protected",
    ]


    for field in configuration_fields:

        old_value = baseline_config.get(
            field
        )

        new_value = current_config.get(
            field
        )

        if old_value != new_value:

            changed_fields.append(
                {
                    "field":
                        field,

                    "old_value":
                        old_value,

                    "new_value":
                        new_value,
                }
            )


    if changed_fields:
        status = "CHANGED"
    else:
        status = "MATCH"


    return {
        "layer":
            "SECURITY_STATE",

        "card_family":
            "NTAG215",

        "status":
            status,

        "changed_field_count":
            len(changed_fields),

        "changed_fields":
            changed_fields,

        "reason":
            None,
    }


# ==================================================
# MIFARE CLASSIC SECURITY VERIFICATION
# ==================================================

def normalize_sector_keys(
    sectors
):
    """
    Normalize MIFARE sector dictionary keys.
    """

    return {
        str(sector): evidence
        for sector, evidence
        in sectors.items()
    }


def verify_mifare_security_state(
    current_security,
    baseline_security
):
    """
    Compare safe MIFARE Classic sector-trailer
    security evidence.

    Key A and Key B are not compared because
    N3 deliberately does not store them.
    """

    current_sectors = (
        normalize_sector_keys(
            current_security.get(
                "sectors",
                {}
            )
        )
    )

    baseline_sectors = (
        normalize_sector_keys(
            baseline_security.get(
                "sectors",
                {}
            )
        )
    )


    changed_fields = []


    all_sectors = (
        set(current_sectors.keys())
        |
        set(baseline_sectors.keys())
    )


    all_sectors = sorted(
        all_sectors,
        key=lambda sector: int(sector)
    )


    fields_to_check = [
        "sector_trailer_block",
        "access_bytes",
        "general_purpose_byte",
        "access_bits_redundancy_valid",
        "c1_redundancy_valid",
        "c2_redundancy_valid",
        "c3_redundancy_valid",
        "access_conditions",
    ]


    for sector_number in all_sectors:

        old_sector = baseline_sectors.get(
            sector_number
        )

        new_sector = current_sectors.get(
            sector_number
        )


        # --------------------------------------------------
        # ENTIRE SECTOR EVIDENCE APPEARED/DISAPPEARED
        # --------------------------------------------------

        if old_sector is None or new_sector is None:

            trailer_block = (
                int(sector_number) * 4
                + 3
            )

            changed_fields.append(
                {
                    "sector_number":
                        int(sector_number),

                    "sector_trailer_block":
                        trailer_block,

                    "field":
                        "sector_security_evidence",

                    "old_value":
                        old_sector,

                    "new_value":
                        new_sector,
                }
            )

            continue


        # --------------------------------------------------
        # COMPARE SAFE SECURITY FIELDS
        # --------------------------------------------------

        for field in fields_to_check:

            old_value = old_sector.get(
                field
            )

            new_value = new_sector.get(
                field
            )

            if old_value == new_value:
                continue


            trailer_block = (
                new_sector.get(
                    "sector_trailer_block"
                )
                or old_sector.get(
                    "sector_trailer_block"
                )
                or (
                    int(sector_number) * 4
                    + 3
                )
            )


            changed_fields.append(
                {
                    "sector_number":
                        int(sector_number),

                    "sector_trailer_block":
                        trailer_block,

                    "field":
                        field,

                    "old_value":
                        old_value,

                    "new_value":
                        new_value,
                }
            )


    if changed_fields:
        status = "CHANGED"
    else:
        status = "MATCH"


    return {
        "layer":
            "SECURITY_STATE",

        "card_family":
            "MIFARE_CLASSIC_1K",

        "status":
            status,

        "changed_field_count":
            len(changed_fields),

        "changed_fields":
            changed_fields,

        "key_a_compared":
            False,

        "key_b_compared":
            False,

        "reason":
            None,
    }


# ==================================================
# FAMILY-AWARE SECURITY DISPATCHER
# ==================================================

def verify_security_state(
    canonical_scan,
    baseline
):
    """
    Compare family-specific security evidence.

    NTAG215
        -> lock/configuration state

    MIFARE Classic 1K
        -> sector access/security state
    """

    current_security = (
        canonical_scan.get(
            "security_state"
        )
    )

    baseline_security = baseline.get(
        "security_state"
    )


    validation_error = (
        validate_security_evidence(
            current_security,
            baseline_security
        )
    )

    if validation_error is not None:
        return validation_error


    card_family = get_card_family(
        canonical_scan,
        baseline
    )


    if card_family == "NTAG215":

        return verify_ntag_security_state(
            current_security,
            baseline_security
        )


    if (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        return verify_mifare_security_state(
            current_security,
            baseline_security
        )


    return {
        "layer":
            "SECURITY_STATE",

        "card_family":
            card_family,

        "status":
            "INSUFFICIENT_EVIDENCE",

        "changed_field_count":
            0,

        "changed_fields":
            [],

        "reason":
            (
                "Security verification is not "
                "implemented for this NFC family."
            ),
    }
# --------------------------------------------------
# N3 FAMILY-AWARE SECURITY-STATE EXTRACTION
# --------------------------------------------------


# ==================================================
# COMMON HELPERS
# ==================================================

def bytes_to_hex(values):
    """
    Convert integer byte values into canonical
    uppercase hexadecimal representation.
    """

    if values is None:
        return None

    return " ".join(
        f"{value:02X}"
        for value in values
    )


# ==================================================
# NTAG215 HELPERS
# ==================================================

def page_to_bytes(page_data):
    """
    Convert a canonical NTAG page string such as

    "00 00 FF 00"

    into integer byte values.
    """

    if not page_data:
        return None

    try:

        values = [
            int(value, 16)
            for value in str(page_data).split()
        ]

    except ValueError:

        return None

    if len(values) != 4:
        return None

    return values


def get_memory_page(
    memory_pages,
    page_number
):
    """
    Get one NTAG memory page regardless of whether
    the key is stored as int or string.
    """

    if page_number in memory_pages:
        return memory_pages[page_number]

    string_page = str(
        page_number
    )

    if string_page in memory_pages:
        return memory_pages[string_page]

    return None


# ==================================================
# NTAG215 SECURITY STATE
# ==================================================

def extract_ntag215_security_state(
    canonical_scan
):
    """
    Extract observable NTAG215 security state.

    N3 does NOT store PWD or PACK.
    """

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    card_type = card_info.get(
        "card_type"
    )

    card_family = card_info.get(
        "card_family"
    )


    # --------------------------------------------------
    # FAMILY CHECK
    # --------------------------------------------------

    if (
        card_family != "NTAG215"
        and card_type != "NTAG215"
    ):

        return {
            "supported": False,
            "card_family": card_family,
            "card_type": card_type,
            "evidence_complete": False,
            "reason": (
                "This security extractor supports "
                "NTAG215 only."
            ),
        }


    memory_pages = canonical_scan.get(
        "memory_pages",
        {}
    )


    # --------------------------------------------------
    # REQUIRED SECURITY PAGES
    # --------------------------------------------------

    page_2 = page_to_bytes(
        get_memory_page(
            memory_pages,
            2
        )
    )

    page_130 = page_to_bytes(
        get_memory_page(
            memory_pages,
            130
        )
    )

    page_131 = page_to_bytes(
        get_memory_page(
            memory_pages,
            131
        )
    )

    page_132 = page_to_bytes(
        get_memory_page(
            memory_pages,
            132
        )
    )


    missing_pages = []

    if page_2 is None:
        missing_pages.append(2)

    if page_130 is None:
        missing_pages.append(130)

    if page_131 is None:
        missing_pages.append(131)

    if page_132 is None:
        missing_pages.append(132)


    if missing_pages:

        return {
            "supported": True,
            "card_family": "NTAG215",
            "card_type": "NTAG215",
            "evidence_complete": False,
            "missing_pages": missing_pages,
        }


    # --------------------------------------------------
    # STATIC LOCK BYTES
    # --------------------------------------------------

    static_lock_bytes = [
        page_2[2],
        page_2[3],
    ]


    # --------------------------------------------------
    # DYNAMIC LOCK BYTES
    # --------------------------------------------------

    dynamic_lock_bytes = [
        page_130[0],
        page_130[1],
        page_130[2],
    ]


    # --------------------------------------------------
    # CONFIGURATION PAGE 0
    # --------------------------------------------------

    auth0 = page_131[3]

    password_protection_enabled = (
        auth0 <= 0x86
    )


    # --------------------------------------------------
    # CONFIGURATION PAGE 1
    # --------------------------------------------------

    access_byte = page_132[0]


    # Bit 7 = PROT
    prot = (
        access_byte >> 7
    ) & 0x01


    # Bit 6 = CFGLCK
    config_lock = (
        access_byte >> 6
    ) & 0x01


    # Bit 4 = NFC_CNT_EN
    nfc_counter_enabled = (
        access_byte >> 4
    ) & 0x01


    # Bit 3 = NFC_CNT_PWD_PROT
    nfc_counter_password_protected = (
        access_byte >> 3
    ) & 0x01


    # Bits 0-2 = AUTHLIM
    authlim = (
        access_byte & 0x07
    )


    # --------------------------------------------------
    # PROTECTION MODE
    # --------------------------------------------------

    if not password_protection_enabled:

        protection_mode = "DISABLED"

    elif prot == 0:

        protection_mode = "WRITE_PROTECTED"

    else:

        protection_mode = (
            "READ_WRITE_PROTECTED"
        )


    # --------------------------------------------------
    # FINAL NTAG SECURITY STATE
    # --------------------------------------------------

    return {

        "supported": True,

        "card_family": "NTAG215",

        "card_type": "NTAG215",

        "evidence_complete": True,

        "sensitive_credentials_stored":
            False,

        "static_lock_bytes":
            bytes_to_hex(
                static_lock_bytes
            ),

        "dynamic_lock_bytes":
            bytes_to_hex(
                dynamic_lock_bytes
            ),

        "configuration": {

            "auth0_page":
                auth0,

            "auth0_hex":
                f"{auth0:02X}",

            "password_protection_enabled":
                password_protection_enabled,

            "protection_mode":
                protection_mode,

            "configuration_locked":
                bool(
                    config_lock
                ),

            "auth_limit":
                authlim,

            "nfc_counter_enabled":
                bool(
                    nfc_counter_enabled
                ),

            "nfc_counter_password_protected":
                bool(
                    nfc_counter_password_protected
                ),
        },

        "raw_configuration": {

            "page_131_cfg0":
                bytes_to_hex(
                    page_131
                ),

            "page_132_cfg1":
                bytes_to_hex(
                    page_132
                ),
        },
    }


# ==================================================
# MIFARE CLASSIC HELPERS
# ==================================================

def get_memory_block(
    memory_blocks,
    block_number
):
    """
    Retrieve one MIFARE block regardless of whether
    the dictionary key is int or string.
    """

    if block_number in memory_blocks:

        return memory_blocks[
            block_number
        ]

    string_block = str(
        block_number
    )

    if string_block in memory_blocks:

        return memory_blocks[
            string_block
        ]

    return None


def parse_hex_byte(value):
    """
    Convert one normal hexadecimal byte into int.

    Masked values such as ** are rejected.
    """

    if value is None:
        return None

    value = str(
        value
    ).strip()

    if value in {
        "**",
        "??",
    }:
        return None

    try:

        number = int(
            value,
            16
        )

    except ValueError:

        return None

    if not 0 <= number <= 255:
        return None

    return number


def decode_mifare_access_bits(
    access_byte_6,
    access_byte_7,
    access_byte_8
):
    """
    Decode the three MIFARE Classic access bytes.

    The access configuration contains C1, C2 and C3
    bits for each relative block in the sector.

    It also contains inverted copies of those bits.
    N3 checks that redundancy for consistency.

    Returns security evidence only.
    It does not expose authentication keys.
    """

    b6 = access_byte_6
    b7 = access_byte_7
    b8 = access_byte_8


    # --------------------------------------------------
    # ORIGINAL AND INVERTED NIBBLES
    # --------------------------------------------------

    inverted_c2 = (
        b6 >> 4
    ) & 0x0F

    inverted_c1 = (
        b6
        & 0x0F
    )

    c1 = (
        b7 >> 4
    ) & 0x0F

    inverted_c3 = (
        b7
        & 0x0F
    )

    c3 = (
        b8 >> 4
    ) & 0x0F

    c2 = (
        b8
        & 0x0F
    )


    # --------------------------------------------------
    # REDUNDANCY CHECK
    # --------------------------------------------------

    c1_valid = (
        ((~c1) & 0x0F)
        == inverted_c1
    )

    c2_valid = (
        ((~c2) & 0x0F)
        == inverted_c2
    )

    c3_valid = (
        ((~c3) & 0x0F)
        == inverted_c3
    )

    redundancy_valid = (
        c1_valid
        and c2_valid
        and c3_valid
    )


    # --------------------------------------------------
    # ACCESS CONDITION FOR EACH RELATIVE BLOCK
    # --------------------------------------------------

    access_conditions = {}

    for relative_block in range(4):

        c1_bit = (
            c1 >> relative_block
        ) & 0x01

        c2_bit = (
            c2 >> relative_block
        ) & 0x01

        c3_bit = (
            c3 >> relative_block
        ) & 0x01

        access_conditions[
            str(relative_block)
        ] = {

            "relative_block":
                relative_block,

            "c1":
                c1_bit,

            "c2":
                c2_bit,

            "c3":
                c3_bit,

            "triplet":
                (
                    f"{c1_bit}"
                    f"{c2_bit}"
                    f"{c3_bit}"
                ),
        }


    return {

        "redundancy_valid":
            redundancy_valid,

        "c1_redundancy_valid":
            c1_valid,

        "c2_redundancy_valid":
            c2_valid,

        "c3_redundancy_valid":
            c3_valid,

        "access_conditions":
            access_conditions,
    }


# ==================================================
# MIFARE CLASSIC 1K SECURITY STATE
# ==================================================

def extract_mifare_classic_1k_security_state(
    canonical_scan
):
    """
    Extract observable MIFARE Classic 1K security
    configuration from sector trailers.

    N3 intentionally does NOT store Key A or Key B.

    Only safe observable evidence is retained:
    - access bytes
    - general purpose byte
    - decoded C1/C2/C3 conditions
    - access-bit redundancy status
    """

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    card_family = card_info.get(
        "card_family"
    )

    card_type = card_info.get(
        "card_type"
    )


    # --------------------------------------------------
    # FAMILY CHECK
    # --------------------------------------------------

    if (
        card_family
        != "MIFARE_CLASSIC_1K"
    ):

        return {

            "supported": False,

            "card_family":
                card_family,

            "card_type":
                card_type,

            "evidence_complete":
                False,

            "reason": (
                "This security extractor supports "
                "MIFARE Classic 1K only."
            ),
        }


    memory_blocks = canonical_scan.get(
        "memory_blocks",
        {}
    )


    sectors = {}

    missing_sector_trailers = []

    malformed_sector_trailers = []


    # --------------------------------------------------
    # 16 MIFARE CLASSIC 1K SECTORS
    # --------------------------------------------------

    for sector_number in range(16):

        trailer_block_number = (
            sector_number * 4
            + 3
        )

        block_entry = get_memory_block(
            memory_blocks,
            trailer_block_number
        )


        # --------------------------------------------------
        # TRAILER MISSING
        # --------------------------------------------------

        if not isinstance(
            block_entry,
            dict
        ):

            missing_sector_trailers.append(
                trailer_block_number
            )

            continue


        block_data = block_entry.get(
            "data"
        )


        if not block_data:

            malformed_sector_trailers.append(
                trailer_block_number
            )

            continue


        tokens = str(
            block_data
        ).strip().split()


        # Sector trailer must still contain
        # 16 byte positions even though keys
        # are represented by **.
        if len(tokens) != 16:

            malformed_sector_trailers.append(
                trailer_block_number
            )

            continue


        # --------------------------------------------------
        # SECURITY CONFIGURATION BYTES
        # --------------------------------------------------

        access_byte_6 = parse_hex_byte(
            tokens[6]
        )

        access_byte_7 = parse_hex_byte(
            tokens[7]
        )

        access_byte_8 = parse_hex_byte(
            tokens[8]
        )

        general_purpose_byte = (
            parse_hex_byte(
                tokens[9]
            )
        )


        if (
            access_byte_6 is None
            or access_byte_7 is None
            or access_byte_8 is None
            or general_purpose_byte is None
        ):

            malformed_sector_trailers.append(
                trailer_block_number
            )

            continue


        access_result = (
            decode_mifare_access_bits(
                access_byte_6,
                access_byte_7,
                access_byte_8
            )
        )


        # --------------------------------------------------
        # STORE SAFE SECTOR EVIDENCE
        # --------------------------------------------------

        sectors[
            str(sector_number)
        ] = {

            "sector_number":
                sector_number,

            "sector_trailer_block":
                trailer_block_number,

            "access_bytes":
                (
                    f"{access_byte_6:02X} "
                    f"{access_byte_7:02X} "
                    f"{access_byte_8:02X}"
                ),

            "general_purpose_byte":
                f"{general_purpose_byte:02X}",

            "access_bits_redundancy_valid":
                access_result[
                    "redundancy_valid"
                ],

            "c1_redundancy_valid":
                access_result[
                    "c1_redundancy_valid"
                ],

            "c2_redundancy_valid":
                access_result[
                    "c2_redundancy_valid"
                ],

            "c3_redundancy_valid":
                access_result[
                    "c3_redundancy_valid"
                ],

            "access_conditions":
                access_result[
                    "access_conditions"
                ],

            # Explicit evidence that keys
            # are intentionally excluded.
            "key_a_stored":
                False,

            "key_b_stored":
                False,
        }


    # --------------------------------------------------
    # EVIDENCE COMPLETENESS
    # --------------------------------------------------

    evidence_complete = (
        len(
            missing_sector_trailers
        ) == 0
        and
        len(
            malformed_sector_trailers
        ) == 0
        and
        len(sectors) == 16
    )


    # --------------------------------------------------
    # FINAL MIFARE SECURITY STATE
    # --------------------------------------------------

    return {

        "supported":
            True,

        "card_family":
            "MIFARE_CLASSIC_1K",

        "card_type":
            "MIFARE Classic 1K",

        "evidence_complete":
            evidence_complete,

        "sensitive_credentials_stored":
            False,

        "key_storage_policy":
            "KEY_A_AND_KEY_B_NOT_STORED",

        "expected_sector_count":
            16,

        "parsed_security_sectors":
            len(sectors),

        "missing_sector_trailer_blocks":
            missing_sector_trailers,

        "malformed_sector_trailer_blocks":
            malformed_sector_trailers,

        "sectors":
            sectors,
    }


# ==================================================
# FAMILY-AWARE SECURITY DISPATCHER
# ==================================================

def extract_security_state(
    canonical_scan
):
    """
    Automatically select the correct
    security-state extractor based on NFC family.

    NTAG215
        -> NTAG security configuration

    MIFARE Classic 1K
        -> sector-trailer access configuration
    """

    card_info = canonical_scan.get(
        "card_info",
        {}
    )

    card_family = card_info.get(
        "card_family"
    )

    card_type = card_info.get(
        "card_type"
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if (
        card_family == "NTAG215"
        or card_type == "NTAG215"
    ):

        return (
            extract_ntag215_security_state(
                canonical_scan
            )
        )


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    if (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        return (
            extract_mifare_classic_1k_security_state(
                canonical_scan
            )
        )


    # --------------------------------------------------
    # UNSUPPORTED FAMILY
    # --------------------------------------------------

    return {

        "supported":
            False,

        "card_family":
            card_family,

        "card_type":
            card_type,

        "evidence_complete":
            False,

        "reason":
            (
                "Security-state extraction is not "
                "implemented for this NFC family."
            ),
    }
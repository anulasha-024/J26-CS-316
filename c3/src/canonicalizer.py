# --------------------------------------------------
# HEX NORMALIZATION
# --------------------------------------------------

def normalize_hex(value):
    """
    Convert hexadecimal text into one consistent format.

    Example:
    '04 33 fb 8d' -> '04 33 FB 8D'

    Unknown bytes such as ?? are preserved.
    """

    if value is None:
        return None

    parts = str(value).strip().split()

    return " ".join(
        part.upper()
        for part in parts
    )


# --------------------------------------------------
# INTEGER CONVERSION
# --------------------------------------------------

def safe_int(value):
    """
    Convert a value to integer when possible.

    If conversion is not possible,
    return None.
    """

    if value is None:
        return None

    try:
        return int(value)

    except (TypeError, ValueError):
        return None


# --------------------------------------------------
# CARD FAMILY
# --------------------------------------------------

def get_card_family(card_info):
    """
    Return the card family detected by parser.py.
    """

    family = card_info.get(
        "N3 card family"
    )

    if family is None:
        return "UNKNOWN"

    return str(family).strip().upper()


# --------------------------------------------------
# CANONICAL CARD INFORMATION
# --------------------------------------------------

def canonicalize_card_info(card_info):
    """
    Convert important NFC card information
    into one consistent family-aware format.

    Supports:
    - NTAG215
    - MIFARE Classic 1K
    """

    card_family = get_card_family(
        card_info
    )


    # --------------------------------------------------
    # COMMON CARD INFORMATION
    # --------------------------------------------------

    canonical_info = {

        "device_type": card_info.get(
            "Device type"
        ),

        "card_family": card_family,

        "uid": normalize_hex(
            card_info.get("UID")
        ),

        "atqa": normalize_hex(
            card_info.get("ATQA")
        ),

        "sak": normalize_hex(
            card_info.get("SAK")
        ),

        "memory_unit": card_info.get(
            "N3 memory unit"
        ),

        "parsed_memory_units": safe_int(
            card_info.get(
                "N3 parsed memory units"
            )
        ),

        "unknown_byte_count": safe_int(
            card_info.get(
                "N3 unknown byte count"
            )
        ),
    }


    # --------------------------------------------------
    # NTAG215 INFORMATION
    # --------------------------------------------------

    if card_family == "NTAG215":

        canonical_info[
            "card_type"
        ] = card_info.get(
            "NTAG/Ultralight type"
        )

        canonical_info[
            "pages_total"
        ] = safe_int(
            card_info.get(
                "Pages total"
            )
        )

        canonical_info[
            "pages_read"
        ] = safe_int(
            card_info.get(
                "Pages read"
            )
        )

        canonical_info[
            "blocks_total"
        ] = None

        canonical_info[
            "sectors_total"
        ] = None

        canonical_info[
            "data_format_version"
        ] = None


    # --------------------------------------------------
    # MIFARE CLASSIC 1K INFORMATION
    # --------------------------------------------------

    elif card_family == "MIFARE_CLASSIC_1K":

        mifare_type = card_info.get(
            "Mifare Classic type"
        )

        canonical_info[
            "card_type"
        ] = (
            f"MIFARE Classic {mifare_type}"
            if mifare_type
            else "MIFARE Classic"
        )

        canonical_info[
            "mifare_classic_type"
        ] = mifare_type

        canonical_info[
            "pages_total"
        ] = None

        canonical_info[
            "pages_read"
        ] = None

        canonical_info[
            "blocks_total"
        ] = safe_int(
            card_info.get(
                "N3 expected blocks"
            )
        )

        canonical_info[
            "sectors_total"
        ] = safe_int(
            card_info.get(
                "N3 expected sectors"
            )
        )

        canonical_info[
            "data_format_version"
        ] = safe_int(
            card_info.get(
                "Data format version"
            )
        )


    # --------------------------------------------------
    # UNKNOWN / UNSUPPORTED FAMILY
    # --------------------------------------------------

    else:

        canonical_info[
            "card_type"
        ] = None

        canonical_info[
            "pages_total"
        ] = None

        canonical_info[
            "pages_read"
        ] = None

        canonical_info[
            "blocks_total"
        ] = None

        canonical_info[
            "sectors_total"
        ] = None

        canonical_info[
            "data_format_version"
        ] = None


    return canonical_info


# --------------------------------------------------
# NTAG PAGE CANONICALIZATION
# --------------------------------------------------

def canonicalize_pages(pages):
    """
    Normalize NTAG memory pages.

    Example:

    Page 4:
    '03 20 d1 01'

    becomes:

    4: '03 20 D1 01'
    """

    canonical_pages = {}

    for page_number, page_data in pages.items():

        canonical_pages[
            int(page_number)
        ] = normalize_hex(
            page_data
        )

    return canonical_pages


# --------------------------------------------------
# MIFARE CLASSIC BLOCK HELPERS
# --------------------------------------------------

def get_mifare_classic_1k_sector(
    block_number
):
    """
    MIFARE Classic 1K:

    64 blocks
    16 sectors
    4 blocks per sector
    """

    block_number = int(
        block_number
    )

    if (
        block_number < 0
        or block_number > 63
    ):
        return None

    return block_number // 4


def is_mifare_classic_1k_sector_trailer(
    block_number
):
    """
    Sector trailer blocks are:

    3, 7, 11, 15 ... 63
    """

    block_number = int(
        block_number
    )

    if (
        block_number < 0
        or block_number > 63
    ):
        return False

    return block_number % 4 == 3


def get_mifare_block_type(
    block_number
):
    """
    Classify a MIFARE Classic 1K block.
    """

    block_number = int(
        block_number
    )

    if block_number == 0:
        return "MANUFACTURER_BLOCK"

    if (
        is_mifare_classic_1k_sector_trailer(
            block_number
        )
    ):
        return "SECTOR_TRAILER"

    return "DATA_BLOCK"


# --------------------------------------------------
# MIFARE KEY-SAFE REPRESENTATION
# --------------------------------------------------

def build_mifare_sector_trailer_evidence(
    block_data
):
    """
    Create a security-safe representation of
    a MIFARE Classic sector trailer.

    Sector trailer:

    Bytes 0-5   = Key A
    Bytes 6-8   = Access Bits
    Byte 9      = General Purpose Byte
    Bytes 10-15 = Key B

    N3 should not unnecessarily store or expose
    secret key values inside its canonical evidence.

    Therefore:
    - Key A bytes are masked
    - Access bytes are preserved
    - GP byte is preserved
    - Key B bytes are masked
    """

    normalized = normalize_hex(
        block_data
    )

    if normalized is None:
        return None

    parts = normalized.split()

    if len(parts) != 16:
        return normalized

    safe_parts = (
        ["**"] * 6
        + parts[6:10]
        + ["**"] * 6
    )

    return " ".join(
        safe_parts
    )


# --------------------------------------------------
# MIFARE BLOCK CANONICALIZATION
# --------------------------------------------------

def canonicalize_mifare_blocks(
    blocks
):
    """
    Convert MIFARE Classic blocks into
    a family-aware canonical structure.

    Each block contains:

    - block_number
    - sector_number
    - block_type
    - data

    Sector trailer keys are masked from
    canonical evidence.
    """

    canonical_blocks = {}

    for block_number, block_data in blocks.items():

        block_number = int(
            block_number
        )

        sector_number = (
            get_mifare_classic_1k_sector(
                block_number
            )
        )

        block_type = (
            get_mifare_block_type(
                block_number
            )
        )


        # --------------------------------------------------
        # SECTOR TRAILER
        # --------------------------------------------------

        if block_type == "SECTOR_TRAILER":

            canonical_data = (
                build_mifare_sector_trailer_evidence(
                    block_data
                )
            )


        # --------------------------------------------------
        # NORMAL / MANUFACTURER BLOCK
        # --------------------------------------------------

        else:

            canonical_data = normalize_hex(
                block_data
            )


        canonical_blocks[
            block_number
        ] = {

            "block_number": block_number,

            "sector_number": sector_number,

            "block_type": block_type,

            "data": canonical_data,
        }


    return canonical_blocks


# --------------------------------------------------
# CANONICALIZE COMPLETE SCAN
# --------------------------------------------------

def canonicalize_scan(
    card_info,
    memory_units
):
    """
    Create one standard N3 representation
    of the parsed NFC scan.

    Automatically selects the correct
    memory representation based on card family.

    NTAG215:
        memory_pages

    MIFARE Classic 1K:
        memory_blocks
    """

    canonical_card_info = (
        canonicalize_card_info(
            card_info
        )
    )

    card_family = (
        canonical_card_info.get(
            "card_family"
        )
    )


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        canonical_pages = (
            canonicalize_pages(
                memory_units
            )
        )

        canonical_scan = {

            "card_info":
                canonical_card_info,

            "memory_pages":
                canonical_pages,

            # Keep this field available so
            # family-aware code can use a
            # predictable structure.
            "memory_blocks": {},
        }

        return canonical_scan


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    if (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        canonical_blocks = (
            canonicalize_mifare_blocks(
                memory_units
            )
        )

        canonical_scan = {

            "card_info":
                canonical_card_info,

            # Preserve this field for
            # backward compatibility with
            # existing NTAG code.
            "memory_pages": {},

            "memory_blocks":
                canonical_blocks,
        }

        return canonical_scan


    # --------------------------------------------------
    # UNKNOWN FAMILY
    # --------------------------------------------------

    canonical_scan = {

        "card_info":
            canonical_card_info,

        "memory_pages": {},

        "memory_blocks": {},
    }

    return canonical_scan
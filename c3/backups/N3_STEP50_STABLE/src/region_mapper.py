# --------------------------------------------------
# N3 FAMILY-AWARE REGION MAPPER
# --------------------------------------------------


# ==================================================
# NTAG215 REGION MAPPING
# ==================================================

def map_ntag215_page_to_region(
    page_number
):
    """
    Convert an NTAG215 memory page number into
    a logical N3 memory region.
    """

    try:
        page_number = int(
            page_number
        )

    except (TypeError, ValueError):

        return "UNKNOWN_REGION"


    # --------------------------------------------------
    # PAGES 0-1
    # UID / MANUFACTURER INFORMATION
    # --------------------------------------------------

    if 0 <= page_number <= 1:

        return "MANUFACTURER_UID"


    # --------------------------------------------------
    # PAGE 2
    # STATIC LOCK AREA
    # --------------------------------------------------

    if page_number == 2:

        return "STATIC_LOCK"


    # --------------------------------------------------
    # PAGE 3
    # CAPABILITY CONTAINER
    # --------------------------------------------------

    if page_number == 3:

        return "CAPABILITY_CONTAINER"


    # --------------------------------------------------
    # PAGES 4-129
    # USER / APPLICATION MEMORY
    # --------------------------------------------------

    if 4 <= page_number <= 129:

        return "USER_MEMORY"


    # --------------------------------------------------
    # PAGE 130
    # DYNAMIC LOCK AREA
    # --------------------------------------------------

    if page_number == 130:

        return "DYNAMIC_LOCK"


    # --------------------------------------------------
    # PAGES 131-132
    # SECURITY CONFIGURATION
    # --------------------------------------------------

    if 131 <= page_number <= 132:

        return "SECURITY_CONFIGURATION"


    # --------------------------------------------------
    # PAGE 133
    # PASSWORD AREA
    # --------------------------------------------------

    if page_number == 133:

        return "PASSWORD_AREA"


    # --------------------------------------------------
    # PAGE 134
    # AUTHENTICATION AREA
    # --------------------------------------------------

    if page_number == 134:

        return "AUTHENTICATION_AREA"


    return "UNKNOWN_REGION"


# ==================================================
# ADD NTAG215 REGION INFORMATION
# ==================================================

def add_ntag215_regions(
    changed_pages
):
    """
    Add logical NTAG215 region information to
    every changed page.
    """

    mapped_changes = []

    for change in changed_pages:

        mapped_change = dict(
            change
        )

        mapped_change[
            "region"
        ] = map_ntag215_page_to_region(
            change.get(
                "page"
            )
        )

        mapped_changes.append(
            mapped_change
        )

    return mapped_changes


# ==================================================
# MIFARE CLASSIC 1K HELPERS
# ==================================================

def get_mifare_classic_1k_sector(
    block_number
):
    """
    Convert MIFARE Classic 1K block number
    into sector number.

    4 blocks per sector.

    Examples:

    Block 0  -> Sector 0
    Block 4  -> Sector 1
    Block 11 -> Sector 2
    Block 63 -> Sector 15
    """

    try:

        block_number = int(
            block_number
        )

    except (TypeError, ValueError):

        return None


    if (
        block_number < 0
        or block_number > 63
    ):

        return None


    return (
        block_number // 4
    )


def is_mifare_classic_sector_trailer(
    block_number
):
    """
    Return True when the MIFARE Classic 1K
    block is a sector trailer.

    Trailer blocks:

    3, 7, 11, 15 ... 63
    """

    try:

        block_number = int(
            block_number
        )

    except (TypeError, ValueError):

        return False


    if (
        block_number < 0
        or block_number > 63
    ):

        return False


    return (
        block_number % 4
        == 3
    )


# ==================================================
# MIFARE CLASSIC BLOCK TYPE
# ==================================================

def map_mifare_classic_block_type(
    block_number
):
    """
    Determine the logical type of a
    MIFARE Classic 1K block.
    """

    try:

        block_number = int(
            block_number
        )

    except (TypeError, ValueError):

        return "UNKNOWN_BLOCK"


    # Manufacturer block
    if block_number == 0:

        return "MANUFACTURER_BLOCK"


    # Sector trailer
    if (
        is_mifare_classic_sector_trailer(
            block_number
        )
    ):

        return "SECTOR_TRAILER"


    # Remaining blocks
    if 0 <= block_number <= 63:

        return "DATA_BLOCK"


    return "UNKNOWN_BLOCK"


# ==================================================
# MIFARE CLASSIC LOGICAL REGION
# ==================================================

def map_mifare_classic_block_to_region(
    block_number
):
    """
    Convert a MIFARE Classic 1K block into a
    logical N3 region.

    Block 0
        -> MANUFACTURER_UID

    Normal data block
        -> USER_MEMORY

    Sector trailer
        -> SECURITY_CONFIGURATION
    """

    block_type = (
        map_mifare_classic_block_type(
            block_number
        )
    )


    if (
        block_type
        == "MANUFACTURER_BLOCK"
    ):

        return "MANUFACTURER_UID"


    if (
        block_type
        == "DATA_BLOCK"
    ):

        return "USER_MEMORY"


    if (
        block_type
        == "SECTOR_TRAILER"
    ):

        return "SECURITY_CONFIGURATION"


    return "UNKNOWN_REGION"


# ==================================================
# ADD MIFARE CLASSIC REGION INFORMATION
# ==================================================

def add_mifare_classic_regions(
    changed_blocks
):
    """
    Add MIFARE Classic localization information
    to every changed block.

    Adds:

    - sector_number
    - block_number
    - block_type
    - region
    """

    mapped_changes = []


    for change in changed_blocks:

        mapped_change = dict(
            change
        )


        # --------------------------------------------------
        # GET BLOCK NUMBER
        # --------------------------------------------------

        block_number = (
            change.get(
                "block_number"
            )
        )


        if block_number is None:

            block_number = (
                change.get(
                    "block"
                )
            )


        try:

            block_number = int(
                block_number
            )

        except (TypeError, ValueError):

            block_number = None


        # --------------------------------------------------
        # SECTOR NUMBER
        # --------------------------------------------------

        sector_number = (
            change.get(
                "sector_number"
            )
        )


        if sector_number is None:

            sector_number = (
                get_mifare_classic_1k_sector(
                    block_number
                )
            )


        # --------------------------------------------------
        # BLOCK TYPE
        # --------------------------------------------------

        block_type = change.get(
            "block_type"
        )


        if not block_type:

            block_type = (
                map_mifare_classic_block_type(
                    block_number
                )
            )


        # --------------------------------------------------
        # LOGICAL REGION
        # --------------------------------------------------

        region = (
            map_mifare_classic_block_to_region(
                block_number
            )
        )


        # --------------------------------------------------
        # STORE LOCALIZATION
        # --------------------------------------------------

        mapped_change[
            "sector_number"
        ] = sector_number

        mapped_change[
            "block_number"
        ] = block_number

        mapped_change[
            "block_type"
        ] = block_type

        mapped_change[
            "region"
        ] = region


        mapped_changes.append(
            mapped_change
        )


    return mapped_changes


# ==================================================
# FAMILY-AWARE REGION DISPATCHER
# ==================================================

def add_regions_to_raw_changes(
    card_family,
    raw_result
):
    """
    Automatically add family-specific localization
    information to a raw-memory verification result.

    NTAG215:
        changed pages

    MIFARE Classic 1K:
        changed sectors / blocks
    """

    if not raw_result:

        return raw_result


    # --------------------------------------------------
    # NTAG215
    # --------------------------------------------------

    if card_family == "NTAG215":

        changed_pages = raw_result.get(
            "changed_pages",
            []
        )

        raw_result[
            "changed_pages"
        ] = add_ntag215_regions(
            changed_pages
        )

        return raw_result


    # --------------------------------------------------
    # MIFARE CLASSIC 1K
    # --------------------------------------------------

    if (
        card_family
        == "MIFARE_CLASSIC_1K"
    ):

        changed_blocks = raw_result.get(
            "changed_blocks",
            []
        )

        raw_result[
            "changed_blocks"
        ] = add_mifare_classic_regions(
            changed_blocks
        )

        return raw_result


    # --------------------------------------------------
    # UNKNOWN FAMILY
    # --------------------------------------------------

    return raw_result
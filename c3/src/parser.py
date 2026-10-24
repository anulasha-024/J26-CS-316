from pathlib import Path
import argparse
import re


# --------------------------------------------------
# CARD FAMILY CONSTANTS
# --------------------------------------------------

FAMILY_NTAG215 = "NTAG215"

FAMILY_MIFARE_CLASSIC_1K = "MIFARE_CLASSIC_1K"

FAMILY_UNKNOWN = "UNKNOWN"


# --------------------------------------------------
# NORMALIZE TEXT
# --------------------------------------------------

def normalize_text(value):
    """
    Convert a value into a clean uppercase string
    for reliable comparison.
    """

    if value is None:
        return ""

    return str(value).strip().upper()


# --------------------------------------------------
# DETECT CARD FAMILY
# --------------------------------------------------

def detect_card_family(card_info):
    """
    Automatically determine the NFC card family
    using the Flipper Zero header information.

    Current supported families:
    - NTAG215
    - MIFARE Classic 1K
    """

    device_type = normalize_text(
        card_info.get("Device type")
    )


    # --------------------------------------------------
    # NTAG / ULTRALIGHT FAMILY
    # --------------------------------------------------

    if device_type == "NTAG/ULTRALIGHT":

        ntag_type = normalize_text(
            card_info.get(
                "NTAG/Ultralight type"
            )
        )

        if ntag_type == "NTAG215":
            return FAMILY_NTAG215


    # --------------------------------------------------
    # MIFARE CLASSIC FAMILY
    # --------------------------------------------------

    if device_type == "MIFARE CLASSIC":

        mifare_type = normalize_text(
            card_info.get(
                "Mifare Classic type"
            )
        )

        if mifare_type == "1K":
            return FAMILY_MIFARE_CLASSIC_1K


    return FAMILY_UNKNOWN


# --------------------------------------------------
# GET MIFARE CLASSIC SECTOR NUMBER
# --------------------------------------------------

def get_mifare_classic_1k_sector(block_number):
    """
    MIFARE Classic 1K contains:

    16 sectors
    4 blocks per sector
    64 total blocks

    Sector 0  = blocks 0-3
    Sector 1  = blocks 4-7
    ...
    Sector 15 = blocks 60-63
    """

    if block_number < 0 or block_number > 63:
        return None

    return block_number // 4


# --------------------------------------------------
# CHECK MIFARE SECTOR TRAILER
# --------------------------------------------------

def is_mifare_classic_1k_sector_trailer(
    block_number
):
    """
    In MIFARE Classic 1K every fourth block
    is the sector trailer.

    Examples:
    3, 7, 11, 15 ... 63
    """

    if block_number < 0 or block_number > 63:
        return False

    return block_number % 4 == 3


# --------------------------------------------------
# MASK MIFARE KEYS FOR DISPLAY
# --------------------------------------------------

def mask_mifare_sector_trailer(
    block_data
):
    """
    Hide Key A and Key B when printing a
    MIFARE Classic sector trailer.

    Sector trailer layout:

    Bytes 0-5   = Key A
    Bytes 6-8   = Access Bits
    Byte 9      = General Purpose Byte
    Bytes 10-15 = Key B

    The parser still returns the raw acquisition
    internally. This function is only for safer
    terminal display.
    """

    parts = block_data.split()

    if len(parts) != 16:
        return block_data

    masked = (
        ["**"] * 6
        + parts[6:10]
        + ["**"] * 6
    )

    return " ".join(masked)


# --------------------------------------------------
# COUNT UNKNOWN BYTES
# --------------------------------------------------

def count_unknown_bytes(memory_units):
    """
    Count Flipper unknown bytes represented as ??.
    """

    count = 0

    for data in memory_units.values():

        for value in data.split():

            if value == "??":
                count += 1

    return count


# --------------------------------------------------
# PARSE FLIPPER NFC FILE
# --------------------------------------------------

def parse_flipper_nfc(file_path):
    """
    Parse a Flipper Zero .nfc acquisition.

    Automatically supports:

    NTAG215
        -> Page-based memory

    MIFARE Classic 1K
        -> Block-based memory

    Return:
        card_info
        memory_units

    For NTAG215:
        memory_units = pages

    For MIFARE Classic 1K:
        memory_units = blocks
    """

    file_path = Path(file_path)

    text = file_path.read_text(
        encoding="utf-8"
    )

    card_info = {}

    pages = {}

    blocks = {}


    # --------------------------------------------------
    # READ FILE LINE BY LINE
    # --------------------------------------------------

    for raw_line in text.splitlines():

        line = raw_line.strip()


        # --------------------------------------------------
        # IGNORE BLANK LINES / COMMENTS
        # --------------------------------------------------

        if not line:
            continue

        if line.startswith("#"):
            continue


        # --------------------------------------------------
        # DETECT NTAG PAGE
        # --------------------------------------------------

        page_match = re.fullmatch(
            r"Page\s+(\d+):\s*(.*)",
            line,
            flags=re.IGNORECASE,
        )

        if page_match:

            page_number = int(
                page_match.group(1)
            )

            page_data = (
                page_match
                .group(2)
                .strip()
            )

            pages[
                page_number
            ] = page_data

            continue


        # --------------------------------------------------
        # DETECT MIFARE CLASSIC BLOCK
        # --------------------------------------------------

        block_match = re.fullmatch(
            r"Block\s+(\d+):\s*(.*)",
            line,
            flags=re.IGNORECASE,
        )

        if block_match:

            block_number = int(
                block_match.group(1)
            )

            block_data = (
                block_match
                .group(2)
                .strip()
            )

            blocks[
                block_number
            ] = block_data

            continue


        # --------------------------------------------------
        # NORMAL KEY : VALUE FIELD
        # --------------------------------------------------

        if ":" in line:

            key, value = line.split(
                ":",
                1
            )

            card_info[
                key.strip()
            ] = value.strip()


    # --------------------------------------------------
    # AUTOMATIC FAMILY DETECTION
    # --------------------------------------------------

    card_family = detect_card_family(
        card_info
    )

    card_info[
        "N3 card family"
    ] = card_family


    # --------------------------------------------------
    # SELECT CORRECT MEMORY STRUCTURE
    # --------------------------------------------------

    if card_family == FAMILY_NTAG215:

        memory_units = pages

        card_info[
            "N3 memory unit"
        ] = "PAGE"

        card_info[
            "N3 parsed memory units"
        ] = len(pages)


    elif (
        card_family
        == FAMILY_MIFARE_CLASSIC_1K
    ):

        memory_units = blocks

        card_info[
            "N3 memory unit"
        ] = "BLOCK"

        card_info[
            "N3 parsed memory units"
        ] = len(blocks)

        card_info[
            "N3 expected blocks"
        ] = 64

        card_info[
            "N3 expected sectors"
        ] = 16


    else:

        # Unknown family:
        # preserve anything we were able to parse.

        if pages:

            memory_units = pages

            card_info[
                "N3 memory unit"
            ] = "PAGE"

        elif blocks:

            memory_units = blocks

            card_info[
                "N3 memory unit"
            ] = "BLOCK"

        else:

            memory_units = {}

            card_info[
                "N3 memory unit"
            ] = "UNKNOWN"

        card_info[
            "N3 parsed memory units"
        ] = len(
            memory_units
        )


    # --------------------------------------------------
    # UNKNOWN BYTE INFORMATION
    # --------------------------------------------------

    card_info[
        "N3 unknown byte count"
    ] = count_unknown_bytes(
        memory_units
    )


    return (
        card_info,
        memory_units,
    )


# --------------------------------------------------
# DISPLAY NTAG INFORMATION
# --------------------------------------------------

def print_ntag_information(
    card_info,
    pages
):
    """
    Print NTAG215 parser result.
    """

    print(
        "\n--- NTAG215 MEMORY INFORMATION ---"
    )

    print(
        "Pages Total :",
        card_info.get(
            "Pages total"
        )
    )

    print(
        "Pages Read  :",
        card_info.get(
            "Pages read"
        )
    )

    print(
        "Parsed Pages:",
        len(pages)
    )

    print(
        "Unknown Bytes:",
        card_info.get(
            "N3 unknown byte count"
        )
    )


    print(
        "\nFirst Parsed Pages:"
    )

    for page_number in sorted(
        pages.keys()
    )[:13]:

        print(
            f"Page {page_number:03}: "
            f"{pages[page_number]}"
        )


# --------------------------------------------------
# DISPLAY MIFARE CLASSIC INFORMATION
# --------------------------------------------------

def print_mifare_classic_1k_information(
    card_info,
    blocks
):
    """
    Print MIFARE Classic 1K parser result.
    """

    print(
        "\n--- MIFARE CLASSIC 1K MEMORY INFORMATION ---"
    )

    print(
        "Classic Type     :",
        card_info.get(
            "Mifare Classic type"
        )
    )

    print(
        "Data Format Ver. :",
        card_info.get(
            "Data format version"
        )
    )

    print(
        "Expected Sectors :",
        card_info.get(
            "N3 expected sectors"
        )
    )

    print(
        "Expected Blocks  :",
        card_info.get(
            "N3 expected blocks"
        )
    )

    print(
        "Parsed Blocks    :",
        len(blocks)
    )

    print(
        "Unknown Bytes    :",
        card_info.get(
            "N3 unknown byte count"
        )
    )


    # --------------------------------------------------
    # BLOCK COMPLETENESS
    # --------------------------------------------------

    expected_blocks = set(
        range(64)
    )

    parsed_blocks = set(
        blocks.keys()
    )

    missing_blocks = sorted(
        expected_blocks
        - parsed_blocks
    )

    print(
        "Missing Blocks   :",
        missing_blocks
    )


    # --------------------------------------------------
    # SHOW FIRST BLOCKS SAFELY
    # --------------------------------------------------

    print(
        "\nFirst Parsed Blocks:"
    )

    for block_number in sorted(
        blocks.keys()
    )[:12]:

        sector_number = (
            get_mifare_classic_1k_sector(
                block_number
            )
        )

        block_data = blocks[
            block_number
        ]

        if (
            is_mifare_classic_1k_sector_trailer(
                block_number
            )
        ):

            display_data = (
                mask_mifare_sector_trailer(
                    block_data
                )
            )

            block_type = (
                "SECTOR_TRAILER"
            )

        else:

            display_data = block_data

            if block_number == 0:

                block_type = (
                    "MANUFACTURER_BLOCK"
                )

            else:

                block_type = (
                    "DATA_BLOCK"
                )


        print(
            f"Block {block_number:02} "
            f"| Sector {sector_number:02} "
            f"| {block_type}"
        )

        print(
            "  Data :",
            display_data
        )


# --------------------------------------------------
# COMMAND LINE TEST
# --------------------------------------------------

def main():

    print(
        "=== N3 NFC FAMILY-AWARE PARSER ==="
    )


    # --------------------------------------------------
    # COMMAND LINE ARGUMENT
    # --------------------------------------------------

    argument_parser = (
        argparse.ArgumentParser(
            description=(
                "Parse a Flipper Zero NFC file "
                "with automatic card-family detection"
            )
        )
    )

    argument_parser.add_argument(
        "nfc_file",
        help=(
            "Path to the Flipper Zero "
            ".nfc file"
        )
    )

    args = argument_parser.parse_args()

    nfc_file = Path(
        args.nfc_file
    )


    # --------------------------------------------------
    # CHECK FILE EXISTS
    # --------------------------------------------------

    if not nfc_file.exists():

        print(
            "ERROR: NFC file not found."
        )

        print(
            "Path:",
            nfc_file
        )

        return


    # --------------------------------------------------
    # PARSE NFC FILE
    # --------------------------------------------------

    card_info, memory_units = (
        parse_flipper_nfc(
            nfc_file
        )
    )


    # --------------------------------------------------
    # GENERAL INFORMATION
    # --------------------------------------------------

    print(
        "\nSource File :",
        nfc_file
    )

    print(
        "\n--- CARD INFORMATION ---"
    )

    print(
        "Device Type :",
        card_info.get(
            "Device type"
        )
    )

    print(
        "Card Family :",
        card_info.get(
            "N3 card family"
        )
    )

    print(
        "UID         :",
        card_info.get(
            "UID"
        )
    )

    print(
        "ATQA        :",
        card_info.get(
            "ATQA"
        )
    )

    print(
        "SAK         :",
        card_info.get(
            "SAK"
        )
    )

    print(
        "Memory Unit :",
        card_info.get(
            "N3 memory unit"
        )
    )


    # --------------------------------------------------
    # FAMILY-SPECIFIC OUTPUT
    # --------------------------------------------------

    card_family = card_info.get(
        "N3 card family"
    )


    if card_family == FAMILY_NTAG215:

        print(
            "Card Type   :",
            card_info.get(
                "NTAG/Ultralight type"
            )
        )

        print_ntag_information(
            card_info,
            memory_units
        )


    elif (
        card_family
        == FAMILY_MIFARE_CLASSIC_1K
    ):

        print(
            "Card Type   :",
            "MIFARE Classic 1K"
        )

        print_mifare_classic_1k_information(
            card_info,
            memory_units
        )


    else:

        print(
            "Card Type   : UNKNOWN"
        )

        print(
            "\n--- MEMORY INFORMATION ---"
        )

        print(
            "Parsed Memory Units:",
            len(memory_units)
        )


    # --------------------------------------------------
    # FINAL PARSER STATUS
    # --------------------------------------------------

    print(
        "\n--- PARSER RESULT ---"
    )

    print(
        "Detected Family :",
        card_family
    )

    print(
        "Memory Unit     :",
        card_info.get(
            "N3 memory unit"
        )
    )

    print(
        "Parsed Units    :",
        len(memory_units)
    )

    if card_family == FAMILY_UNKNOWN:

        print(
            "Parser Status   : UNSUPPORTED_FAMILY"
        )

    else:

        print(
            "Parser Status   : SUCCESS"
        )


# --------------------------------------------------
# START PROGRAM
# --------------------------------------------------

if __name__ == "__main__":
    main()
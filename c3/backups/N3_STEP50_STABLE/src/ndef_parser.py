# --------------------------------------------------
# N3 FAMILY-AWARE APPLICATION / NDEF EVIDENCE
# --------------------------------------------------


# ==================================================
# NTAG215 HELPERS
# ==================================================

def memory_pages_to_bytes(memory_pages):
    """
    Convert canonical NTAG memory pages into one
    continuous byte sequence.
    """

    data = bytearray()

    page_numbers = sorted(
        memory_pages.keys(),
        key=lambda page: int(page)
    )

    for page_number in page_numbers:

        page_data = memory_pages[
            page_number
        ]

        if not page_data:
            continue

        for hex_byte in str(
            page_data
        ).split():

            data.append(
                int(hex_byte, 16)
            )

    return bytes(data)


# ==================================================
# NTAG215 NDEF MESSAGE EXTRACTION
# ==================================================

def extract_ndef_message(memory_pages):
    """
    Extract an NDEF message from an NFC Forum
    Type 2 Tag TLV structure.

    NTAG215 user/NDEF memory begins at page 4.
    """

    user_pages = {
        page: data
        for page, data
        in memory_pages.items()
        if int(page) >= 4
    }

    raw_bytes = memory_pages_to_bytes(
        user_pages
    )

    index = 0

    while index < len(raw_bytes):

        tlv_type = raw_bytes[index]
        index += 1


        # --------------------------------------------------
        # NULL TLV
        # --------------------------------------------------

        if tlv_type == 0x00:
            continue


        # --------------------------------------------------
        # TERMINATOR TLV
        # --------------------------------------------------

        if tlv_type == 0xFE:
            break


        # --------------------------------------------------
        # LENGTH MUST EXIST
        # --------------------------------------------------

        if index >= len(raw_bytes):
            break

        length = raw_bytes[index]
        index += 1


        # --------------------------------------------------
        # EXTENDED TLV LENGTH
        # --------------------------------------------------

        if length == 0xFF:

            if index + 1 >= len(
                raw_bytes
            ):
                break

            length = (
                raw_bytes[index] << 8
            ) | raw_bytes[index + 1]

            index += 2


        # --------------------------------------------------
        # NDEF MESSAGE TLV
        # --------------------------------------------------

        if tlv_type == 0x03:

            end = index + length

            if end > len(raw_bytes):

                raise ValueError(
                    "Incomplete NDEF message."
                )

            return raw_bytes[
                index:end
            ]


        # --------------------------------------------------
        # SKIP OTHER TLV TYPES
        # --------------------------------------------------

        index += length


    return None


# ==================================================
# NDEF TEXT RECORD PARSER
# ==================================================

def parse_ndef_text_record(
    ndef_message
):
    """
    Parse the first NDEF Text Record.

    Example:

    N3|ID=001|STATUS=ORIGINAL
    """

    if not ndef_message:
        return None

    if len(ndef_message) < 4:

        raise ValueError(
            "Invalid NDEF message."
        )


    header = ndef_message[0]


    short_record = bool(
        header & 0x10
    )

    id_length_present = bool(
        header & 0x08
    )


    type_length = ndef_message[1]

    index = 2


    # --------------------------------------------------
    # PAYLOAD LENGTH
    # --------------------------------------------------

    if short_record:

        payload_length = (
            ndef_message[index]
        )

        index += 1

    else:

        if len(ndef_message) < (
            index + 4
        ):

            raise ValueError(
                "Invalid NDEF payload length."
            )

        payload_length = (
            int.from_bytes(
                ndef_message[
                    index:index + 4
                ],
                byteorder="big"
            )
        )

        index += 4


    # --------------------------------------------------
    # OPTIONAL RECORD ID LENGTH
    # --------------------------------------------------

    if id_length_present:

        if index >= len(
            ndef_message
        ):

            raise ValueError(
                "Invalid NDEF record ID length."
            )

        id_length = (
            ndef_message[index]
        )

        index += 1

    else:

        id_length = 0


    # --------------------------------------------------
    # RECORD TYPE
    # --------------------------------------------------

    record_type = ndef_message[
        index:index + type_length
    ]

    index += type_length


    # Skip optional record ID
    index += id_length


    # --------------------------------------------------
    # PAYLOAD
    # --------------------------------------------------

    payload = ndef_message[
        index:index + payload_length
    ]


    # --------------------------------------------------
    # NON-TEXT RECORD
    # --------------------------------------------------

    if record_type != b"T":

        return {
            "record_type":
                record_type.decode(
                    "utf-8",
                    errors="replace"
                ),

            "text":
                None,
        }


    # --------------------------------------------------
    # TEXT RECORD
    # --------------------------------------------------

    if len(payload) < 1:

        raise ValueError(
            "Invalid NDEF Text Record."
        )


    status_byte = payload[0]


    # Lower 6 bits =
    # language-code length
    language_length = (
        status_byte & 0x3F
    )


    language_start = 1

    language_end = (
        language_start
        + language_length
    )


    language = payload[
        language_start:
        language_end
    ].decode(
        "ascii",
        errors="replace"
    )


    text_bytes = payload[
        language_end:
    ]


    # --------------------------------------------------
    # UTF-16 / UTF-8
    # --------------------------------------------------

    if status_byte & 0x80:

        text = text_bytes.decode(
            "utf-16",
            errors="replace"
        )

        encoding = "UTF-16"

    else:

        text = text_bytes.decode(
            "utf-8",
            errors="replace"
        )

        encoding = "UTF-8"


    return {
        "record_type":
            "TEXT",

        "language":
            language,

        "encoding":
            encoding,

        "text":
            text,
    }


# ==================================================
# NTAG215 APPLICATION / NDEF EVIDENCE
# ==================================================

def extract_ntag215_ndef_evidence(
    canonical_scan
):
    """
    Extract NTAG215 NDEF evidence.

    IMPORTANT:
    This keeps the same structure used by
    existing NTAG trusted baselines.
    """

    memory_pages = canonical_scan.get(
        "memory_pages",
        {}
    )


    ndef_message = (
        extract_ndef_message(
            memory_pages
        )
    )


    # --------------------------------------------------
    # NO NDEF
    # --------------------------------------------------

    if ndef_message is None:

        return {
            "ndef_present":
                False,

            "ndef_hex":
                None,

            "record":
                None,
        }


    # --------------------------------------------------
    # NDEF PRESENT
    # --------------------------------------------------

    record = parse_ndef_text_record(
        ndef_message
    )


    return {
        "ndef_present":
            True,

        "ndef_hex":
            ndef_message.hex(
                " "
            ).upper(),

        "record":
            record,
    }


# ==================================================
# MIFARE CLASSIC HELPERS
# ==================================================

def hex_string_to_bytes(
    hex_string
):
    """
    Convert normal hexadecimal text into bytes.

    Masked / unknown values are not accepted.
    """

    if not hex_string:
        return None

    byte_values = []

    for token in str(
        hex_string
    ).split():

        if token in {
            "**",
            "??",
        }:
            return None

        try:

            value = int(
                token,
                16
            )

        except ValueError:

            return None


        if not 0 <= value <= 255:
            return None


        byte_values.append(
            value
        )


    return bytes(
        byte_values
    )


def decode_mifare_application_text(
    block_data
):
    """
    Decode printable application text from
    a normal MIFARE Classic data block.

    Null-byte padding is removed.

    Example:

    4E 33 7C 4D 46 43 30 30 31 7C 4F 52 47 00 00 00

    becomes:

    N3|MFC001|ORG
    """

    raw_bytes = (
        hex_string_to_bytes(
            block_data
        )
    )

    if raw_bytes is None:
        return None


    # Remove trailing NULL padding
    raw_bytes = raw_bytes.rstrip(
        b"\x00"
    )


    if not raw_bytes:
        return None


    try:

        text = raw_bytes.decode(
            "utf-8"
        )

    except UnicodeDecodeError:

        return None


    # --------------------------------------------------
    # REQUIRE PRINTABLE TEXT
    # --------------------------------------------------

    if not all(
        character.isprintable()
        for character in text
    ):
        return None


    return text


# ==================================================
# MIFARE CLASSIC APPLICATION EVIDENCE
# ==================================================

def extract_mifare_classic_application_evidence(
    canonical_scan
):
    """
    Extract controlled application evidence from
    MIFARE Classic 1K normal DATA_BLOCK entries.

    N3 does not assume that every MIFARE Classic
    card contains an NFC Forum NDEF message.

    For this controlled research card, N3 searches
    for application markers beginning with:

        N3|

    Example:

        N3|MFC001|ORG
    """

    memory_blocks = canonical_scan.get(
        "memory_blocks",
        {}
    )


    markers = []


    # --------------------------------------------------
    # SEARCH NORMAL DATA BLOCKS
    # --------------------------------------------------

    sorted_block_numbers = sorted(
        memory_blocks.keys(),
        key=lambda value: int(value)
    )


    for block_number in (
        sorted_block_numbers
    ):

        block_entry = (
            memory_blocks[
                block_number
            ]
        )


        if not isinstance(
            block_entry,
            dict
        ):
            continue


        block_type = block_entry.get(
            "block_type"
        )


        # Only normal application data blocks
        if block_type != "DATA_BLOCK":
            continue


        block_data = block_entry.get(
            "data"
        )


        text = (
            decode_mifare_application_text(
                block_data
            )
        )


        if text is None:
            continue


        # --------------------------------------------------
        # CONTROLLED N3 APPLICATION MARKER
        # --------------------------------------------------

        if not text.startswith(
            "N3|"
        ):
            continue


        marker = {

            "sector_number":
                block_entry.get(
                    "sector_number"
                ),

            "block_number":
                block_entry.get(
                    "block_number",
                    int(block_number)
                ),

            "block_type":
                block_type,

            "text":
                text,

            "block_hex":
                block_data,
        }


        markers.append(
            marker
        )


    # --------------------------------------------------
    # PRIMARY APPLICATION MARKER
    # --------------------------------------------------

    if markers:

        primary_marker = (
            markers[0]
        )

        application_present = True

    else:

        primary_marker = None

        application_present = False


    # --------------------------------------------------
    # MIFARE APPLICATION EVIDENCE
    # --------------------------------------------------

    return {

        # MIFARE Classic is not being treated
        # as NTAG Type-2 NDEF in this profile.
        "ndef_present":
            False,

        "ndef_hex":
            None,

        "record":
            None,

        "application_evidence_type":
            "MIFARE_CLASSIC_DATA_BLOCK_MARKER",

        "application_present":
            application_present,

        "marker_prefix":
            "N3|",

        "marker_count":
            len(markers),

        "primary_marker":
            primary_marker,

        "markers":
            markers,
    }


# ==================================================
# FAMILY-AWARE APPLICATION DISPATCHER
# ==================================================

def extract_ndef_evidence(
    canonical_scan
):
    """
    Family-aware application evidence dispatcher.

    Existing function name is preserved for
    compatibility with scan_watcher.py and the
    existing NTAG verification pipeline.

    NTAG215:
        NFC Forum Type-2 NDEF evidence

    MIFARE Classic 1K:
        controlled data-block application marker
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
            extract_ntag215_ndef_evidence(
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
            extract_mifare_classic_application_evidence(
                canonical_scan
            )
        )


    # --------------------------------------------------
    # UNSUPPORTED FAMILY
    # --------------------------------------------------

    return {

        "ndef_present":
            False,

        "ndef_hex":
            None,

        "record":
            None,

        "application_evidence_type":
            "UNSUPPORTED",

        "application_present":
            False,

        "reason":
            (
                "Application evidence extraction "
                "is not implemented for this "
                "NFC card family."
            ),
    }
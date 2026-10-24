# --------------------------------------------------
# N3 READER / ACQUISITION METADATA
# --------------------------------------------------


def build_reader_metadata(
    source_file=None,
    reader_name="Flipper Zero",
    acquisition_method="NFC_DUMP_FILE",
    interface_type="FILE_IMPORT",
):
    """
    Build structured metadata describing
    how the NFC evidence was acquired.

    The defaults represent the current
    Flipper Zero .nfc file workflow.

    Later, the same structure can be used
    for Proxmark3 or other supported readers.
    """

    metadata = {
        "reader_name":
            reader_name,

        "acquisition_method":
            acquisition_method,

        "interface_type":
            interface_type,

        "source_file":
            None,
    }

    if source_file is not None:

        metadata[
            "source_file"
        ] = str(
            source_file
        )

    return metadata
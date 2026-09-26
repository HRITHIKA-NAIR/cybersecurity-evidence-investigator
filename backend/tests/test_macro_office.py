from io import BytesIO
from zipfile import ZipFile

from app.parsers.file_reader import (
    read_uploaded_file,
)


def test_reads_macro_enabled_docx_structure_without_execution():
    buffer = BytesIO()

    with ZipFile(
        buffer,
        "w",
    ) as archive:
        archive.writestr(
            "[Content_Types].xml",
            (
                "<Types>"
                "<Override "
                "ContentType='application/vnd.ms-word."
                "document.macroEnabled.main+xml'/>"
                "</Types>"
            ),
        )
        archive.writestr(
            "word/document.xml",
            (
                "<w:document "
                "xmlns:w='urn:test'>"
                "<w:t>Macro document evidence</w:t>"
                "</w:document>"
            ),
        )
        archive.writestr(
            "word/vbaProject.bin",
            b"not-executed",
        )

    result = read_uploaded_file(
        "sample.docm",
        (
            "application/vnd.ms-word."
            "document.macroEnabled.12"
        ),
        buffer.getvalue(),
    )

    assert (
        result["file_info"][
            "detected_type"
        ]
        == ".docm"
    )
    assert (
        "Macro document evidence"
        in result["content"]
    )

    attack_types = {
        finding["attack_type"]
        for finding in result[
            "file_analysis"
        ]["findings"]
    }

    assert (
        "VBA Macro Project Present"
        in attack_types
    )

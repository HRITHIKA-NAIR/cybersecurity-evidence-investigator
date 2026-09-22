from io import BytesIO
from zipfile import ZipFile

from app.detectors.file_detector import (
    analyze_file,
)


def _types(result):
    return {
        finding["attack_type"]
        for finding in result["findings"]
    }


def test_detects_possible_pdf_zip_polyglot():
    buffer = BytesIO()
    buffer.write(
        b"%PDF-1.4\n1 0 obj<<>>endobj\n"
    )

    with ZipFile(
        buffer,
        "a",
    ) as archive:
        archive.writestr(
            "payload.txt",
            "test",
        )

    result = analyze_file(
        "sample.pdf",
        ".pdf",
        "application/pdf",
        ".pdf",
        buffer.getvalue(),
    )

    assert (
        "Possible Polyglot File"
        in _types(result)
    )


def test_detects_fake_verification_lure():
    result = analyze_file(
        "verify.html",
        ".html",
        "text/html",
        "text",
        (
            b"<html><body>"
            b"Verify you are human. "
            b"Paste into PowerShell."
            b"</body></html>"
        ),
    )

    assert (
        "Fake Verification or Update Lure"
        in _types(result)
    )

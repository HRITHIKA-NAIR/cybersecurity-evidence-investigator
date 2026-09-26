from io import BytesIO
from zipfile import ZipFile

import cv2

from app.detectors.qr_detector import inspect_qr
from app.parsers.file_reader import read_uploaded_file


def _qr_png(payload: str) -> bytes:
    encoder = cv2.QRCodeEncoder_create()
    image = encoder.encode(payload)
    image = cv2.resize(
        image,
        None,
        fx=10,
        fy=10,
        interpolation=cv2.INTER_NEAREST,
    )
    image = cv2.copyMakeBorder(
        image,
        40,
        40,
        40,
        40,
        cv2.BORDER_CONSTANT,
        value=255,
    )
    ok, buffer = cv2.imencode(
        ".png",
        image,
    )
    assert ok
    return buffer.tobytes()


def test_decodes_qr_url_from_uploaded_image():
    data = _qr_png(
        "https://example.com/verify"
    )

    result = inspect_qr(
        data,
        ".png",
    )

    assert (
        "https://example.com/verify"
        in result["urls"]
    )
    assert result["payloads"]


def test_decodes_non_url_qr_without_treating_as_url():
    data = _qr_png(
        "reference-code-123"
    )

    result = inspect_qr(
        data,
        ".png",
    )

    assert result["urls"] == []
    assert (
        result["payloads"][0]["payload"]
        == "reference-code-123"
    )


def test_decodes_qr_from_office_media():
    qr = _qr_png(
        "https://example.com/from-office"
    )
    buffer = BytesIO()

    with ZipFile(buffer, "w") as archive:
        archive.writestr(
            "word/document.xml",
            "<document/>",
        )
        archive.writestr(
            "word/media/image1.png",
            qr,
        )

    result = inspect_qr(
        buffer.getvalue(),
        ".docx",
    )

    assert (
        "https://example.com/from-office"
        in result["urls"]
    )


def test_file_reader_accepts_qr_png():
    data = _qr_png(
        "https://example.com/image"
    )

    result = read_uploaded_file(
        "qr.png",
        "image/png",
        data,
    )

    assert result["file_info"]["parser"] == "image"
    assert (
        result["file_analysis"]["qr"]["urls"]
        == ["https://example.com/image"]
    )

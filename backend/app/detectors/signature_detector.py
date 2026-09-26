from __future__ import annotations

import zipfile
from io import BytesIO


def signature_labels(
    data: bytes,
) -> list[str]:
    labels = []
    prefix = data[:1024]

    if b"%PDF-" in prefix:
        labels.append("PDF")

    if zipfile.is_zipfile(
        BytesIO(data)
    ):
        labels.append("ZIP/OOXML")

    if data.startswith(
        b"7z\xbc\xaf'\x1c"
    ):
        labels.append("7Z")

    if data.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        labels.append("PNG")

    if data.startswith(b"\xff\xd8\xff"):
        labels.append("JPEG")

    if data.startswith(
        (b"GIF87a", b"GIF89a")
    ):
        labels.append("GIF")

    if data.startswith(b"BM"):
        labels.append("BMP")

    if (
        len(data) >= 12
        and data[:4] == b"RIFF"
        and data[8:12] == b"WEBP"
    ):
        labels.append("WEBP")

    if data.startswith(b"MZ"):
        labels.append("PE")

    return labels


def polyglot_findings(
    data: bytes,
) -> list[dict]:
    labels = signature_labels(data)

    if len(labels) < 2:
        return []

    return [
        {
            "attack_type": (
                "Possible Polyglot File"
            ),
            "category": "File Metadata",
            "severity": "Medium",
            "confidence": 85,
            "status": "Indicator Present",
            "evidence": [
                "Multiple recognizable file "
                "signatures or structures were "
                "observed: "
                + ", ".join(labels)
            ],
        }
    ]

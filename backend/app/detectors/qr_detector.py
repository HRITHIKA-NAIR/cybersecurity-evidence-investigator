from __future__ import annotations

import zipfile
from io import BytesIO

IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
}
MAX_QR_CANDIDATES = 20
MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024
MAX_QR_PIXELS = 20_000_000


def _decode_image(
    data: bytes,
    source: str,
) -> list[dict]:
    if not data or len(data) > MAX_QR_IMAGE_BYTES:
        return []

    try:
        import cv2
        import numpy as np
    except ImportError:
        return []

    image = cv2.imdecode(
        np.frombuffer(data, dtype=np.uint8),
        cv2.IMREAD_GRAYSCALE,
    )

    if image is None:
        return []

    height, width = image.shape[:2]

    if height * width > MAX_QR_PIXELS:
        return []

    detector = cv2.QRCodeDetector()
    payloads = []

    try:
        ok, decoded, _, _ = (
            detector.detectAndDecodeMulti(
                image
            )
        )
    except (
        cv2.error,
        ValueError,
        TypeError,
    ):
        ok = False
        decoded = ()

    if ok:
        for value in decoded:
            if value:
                payloads.append(
                    {
                        "payload": value,
                        "source": source,
                    }
                )

    if payloads:
        return payloads

    try:
        value, _, _ = (
            detector.detectAndDecode(
                image
            )
        )
    except (
        cv2.error,
        ValueError,
        TypeError,
    ):
        value = ""

    if value:
        payloads.append(
            {
                "payload": value,
                "source": source,
            }
        )

    return payloads


def _office_candidates(
    data: bytes,
) -> list[tuple[str, bytes]]:
    candidates = []

    with zipfile.ZipFile(
        BytesIO(data)
    ) as archive:
        for name in archive.namelist():
            lower = name.lower()

            if not (
                "/media/" in lower
                and any(
                    lower.endswith(extension)
                    for extension
                    in IMAGE_EXTENSIONS
                )
            ):
                continue

            payload = archive.read(name)

            if len(payload) > MAX_QR_IMAGE_BYTES:
                continue

            candidates.append(
                (
                    f"office:{name}",
                    payload,
                )
            )

            if (
                len(candidates)
                >= MAX_QR_CANDIDATES
            ):
                break

    return candidates


def _pdf_candidates(
    data: bytes,
) -> list[tuple[str, bytes]]:
    from pypdf import PdfReader

    candidates = []
    reader = PdfReader(
        BytesIO(data)
    )

    for page_number, page in enumerate(
        reader.pages,
        start=1,
    ):
        for image_number, image in enumerate(
            page.images,
            start=1,
        ):
            payload = getattr(
                image,
                "data",
                b"",
            )

            if (
                not payload
                or len(payload)
                > MAX_QR_IMAGE_BYTES
            ):
                continue

            candidates.append(
                (
                    (
                        "pdf:"
                        f"page-{page_number}:"
                        f"image-{image_number}"
                    ),
                    payload,
                )
            )

            if (
                len(candidates)
                >= MAX_QR_CANDIDATES
            ):
                return candidates

    return candidates


def inspect_qr(
    data: bytes,
    extension: str,
) -> dict:
    try:
        import cv2  # noqa: F401
    except ImportError:
        return {
            "status": "unavailable",
            "reason": "QR decoder is not installed.",
            "candidate_count": 0,
            "payloads": [],
            "urls": [],
        }

    try:
        if extension in IMAGE_EXTENSIONS:
            candidates = [
                ("uploaded-image", data)
            ]

        elif extension in {
            ".docx",
            ".pptx",
            ".xlsx",
        }:
            candidates = _office_candidates(
                data
            )

        elif extension == ".pdf":
            candidates = _pdf_candidates(
                data
            )

        else:
            candidates = []

    except Exception:
        return {
            "status": "error",
            "reason": (
                "QR candidate extraction failed "
                "for this artifact."
            ),
            "candidate_count": 0,
            "payloads": [],
            "urls": [],
        }

    payloads = []

    for source, candidate in candidates[
        :MAX_QR_CANDIDATES
    ]:
        payloads.extend(
            _decode_image(
                candidate,
                source,
            )
        )

    unique = []
    seen = set()

    for item in payloads:
        key = (
            item["payload"],
            item["source"],
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    urls = [
        item["payload"]
        for item in unique
        if item["payload"].lower().startswith(
            ("http://", "https://")
        )
    ]

    return {
        "status": "completed",
        "candidate_count": len(candidates),
        "payloads": unique,
        "urls": list(
            dict.fromkeys(urls)
        ),
    }

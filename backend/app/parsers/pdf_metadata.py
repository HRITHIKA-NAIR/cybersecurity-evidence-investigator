from __future__ import annotations

from io import BytesIO

from pypdf import PdfReader


def inspect_pdf_metadata(
    data: bytes,
) -> tuple[dict, list[str]]:
    reader = PdfReader(
        BytesIO(data)
    )
    metadata = reader.metadata or {}

    result = {
        "page_count": len(
            reader.pages
        ),
        "title": metadata.get(
            "/Title"
        ),
        "author": metadata.get(
            "/Author"
        ),
        "subject": metadata.get(
            "/Subject"
        ),
        "creator": metadata.get(
            "/Creator"
        ),
        "producer": metadata.get(
            "/Producer"
        ),
        "encrypted": bool(
            reader.is_encrypted
        ),
    }
    urls = []

    if reader.is_encrypted:
        return result, urls

    for page in reader.pages:
        annotations = page.get(
            "/Annots",
            [],
        )

        for reference in annotations:
            try:
                annotation = (
                    reference.get_object()
                )
                action = annotation.get(
                    "/A"
                )

                if not action:
                    continue

                uri = action.get(
                    "/URI"
                )

                if (
                    uri
                    and str(uri).lower().startswith(
                        (
                            "http://",
                            "https://",
                        )
                    )
                ):
                    urls.append(str(uri))
            except Exception:
                continue

    return result, list(
        dict.fromkeys(urls)
    )

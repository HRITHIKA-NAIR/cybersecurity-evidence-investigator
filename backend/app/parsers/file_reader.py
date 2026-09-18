from __future__ import annotations

import hashlib
import zipfile
from io import BytesIO
from pathlib import Path

from app.detectors.file_detector import analyze_file
from app.detectors.qr_detector import (
    IMAGE_EXTENSIONS,
    inspect_qr,
)
from app.parsers.archive_parser import parse_archive
from app.parsers.email_parser import parse_email
from app.parsers.excel_parser import parse_excel
from app.parsers.pdf_parser import parse_pdf
from app.parsers.powerpoint_parser import parse_powerpoint
from app.parsers.word_parser import parse_word

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_EXTRACTED_CHARS = 50_000
MAX_ARCHIVE_ITEMS = 500
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100

TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".html",
    ".htm",
    ".svg",
}
SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | IMAGE_EXTENSIONS | {
    ".eml",
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".zip",
}
BINARY_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".zip",
} | IMAGE_EXTENSIONS


class FileReaderError(ValueError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _truncate(text: str) -> tuple[str, bool]:
    text = text.strip()

    if len(text) <= MAX_EXTRACTED_CHARS:
        return text, False

    return text[:MAX_EXTRACTED_CHARS], True


def _decode_text(data: bytes) -> str:
    return data.decode(
        "utf-8-sig",
        errors="replace",
    )


def _inspect_zip(data: bytes) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(
        BytesIO(data)
    ) as archive:
        infos = archive.infolist()

    if len(infos) > MAX_ARCHIVE_ITEMS:
        raise FileReaderError(
            "Archive contains too many items "
            f"(maximum {MAX_ARCHIVE_ITEMS}).",
            413,
        )

    total_uncompressed = sum(
        info.file_size
        for info in infos
    )

    if (
        total_uncompressed
        > MAX_ARCHIVE_UNCOMPRESSED_BYTES
    ):
        raise FileReaderError(
            "Archive expands beyond the safe "
            "processing limit.",
            413,
        )

    for info in infos:
        ratio = (
            info.file_size
            / max(info.compress_size, 1)
        )

        if (
            ratio > MAX_COMPRESSION_RATIO
            and info.file_size > 1024 * 1024
        ):
            raise FileReaderError(
                "Archive has an unsafe "
                "compression ratio.",
                413,
            )

    return infos


def _detect_type(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return ".pdf"

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"

    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"

    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"

    if data.startswith(b"BM"):
        return ".bmp"

    if (
        len(data) >= 12
        and data[:4] == b"RIFF"
        and data[8:12] == b"WEBP"
    ):
        return ".webp"

    if zipfile.is_zipfile(
        BytesIO(data)
    ):
        infos = _inspect_zip(data)
        names = [
            info.filename
            for info in infos
        ]

        if any(
            name.startswith("word/")
            for name in names
        ):
            return ".docx"

        if any(
            name.startswith("ppt/")
            for name in names
        ):
            return ".pptx"

        if any(
            name.startswith("xl/")
            for name in names
        ):
            return ".xlsx"

        return ".zip"

    return "text"


def read_uploaded_file(
    filename: str,
    content_type: str | None,
    data: bytes,
) -> dict:
    safe_name = Path(
        filename or "upload"
    ).name
    extension = Path(
        safe_name
    ).suffix.lower()

    if not data:
        raise FileReaderError(
            "The uploaded file is empty."
        )

    if len(data) > MAX_UPLOAD_BYTES:
        raise FileReaderError(
            "File is too large. Maximum "
            "upload size is 10 MB.",
            413,
        )

    if (
        extension
        not in SUPPORTED_EXTENSIONS
    ):
        raise FileReaderError(
            "Unsupported file type: "
            f"{extension or 'no extension'}.",
            415,
        )

    detected_type = _detect_type(
        data
    )

    equivalent_types = {
        ".jpeg": ".jpg",
    }
    expected_detected = equivalent_types.get(
        extension,
        extension,
    )

    if (
        extension in BINARY_EXTENSIONS
        and detected_type != expected_detected
    ):
        raise FileReaderError(
            "The file content does not "
            "match its extension.",
            415,
        )

    if (
        extension
        in TEXT_EXTENSIONS | {".eml"}
        and detected_type != "text"
    ):
        raise FileReaderError(
            "The file content does not "
            "match its extension.",
            415,
        )

    file_analysis = analyze_file(
        safe_name,
        extension,
        content_type,
        detected_type,
        data,
    )
    qr_analysis = inspect_qr(
        data,
        extension,
    )
    file_analysis["qr"] = qr_analysis
    file_analysis["urls"] = list(
        dict.fromkeys(
            file_analysis.get("urls", [])
            + qr_analysis.get("urls", [])
        )
    )

    readers = {
        ".pdf": parse_pdf,
        ".docx": parse_word,
        ".pptx": parse_powerpoint,
        ".xlsx": parse_excel,
        ".zip": parse_archive,
    }

    email_analysis = None

    try:
        if extension in TEXT_EXTENSIONS:
            text = _decode_text(data)
            parser = "text"

        elif extension in IMAGE_EXTENSIONS:
            text = "\n".join(
                item["payload"]
                for item in qr_analysis[
                    "payloads"
                ]
            )
            parser = "image"

        elif extension == ".eml":
            email_result = parse_email(
                data
            )
            text = email_result[
                "content"
            ]
            email_analysis = (
                email_result[
                    "forensics"
                ]
            )
            parser = "eml"

        else:
            text = readers[
                extension
            ](data)
            parser = extension.lstrip(
                "."
            )

    except FileReaderError:
        raise

    except Exception as exc:
        raise FileReaderError(
            f"Could not read "
            f"{extension} file.",
            422,
        ) from exc

    content, truncated = _truncate(
        text
    )

    result = {
        "content": content,
        "file_analysis": file_analysis,
        "file_info": {
            "filename": safe_name,
            "extension": extension,
            "declared_mime": (
                content_type
            ),
            "detected_type": (
                detected_type
            ),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(
                data
            ).hexdigest(),
            "parser": parser,
            "characters_extracted": (
                len(content)
            ),
            "truncated": truncated,
        },
    }

    if email_analysis is not None:
        result[
            "email_analysis"
        ] = email_analysis

    return result

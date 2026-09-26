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
from app.parsers.archive_parser import (
    parse_7z_archive,
    parse_archive,
)
from app.parsers.attachment_analyzer import (
    analyze_email_attachments,
)
from app.parsers.email_parser import parse_email
from app.parsers.excel_parser import parse_excel
from app.parsers.macro_office_parser import (
    parse_macro_office,
)
from app.parsers.pdf_parser import parse_pdf
from app.parsers.powerpoint_parser import parse_powerpoint
from app.parsers.word_parser import parse_word
from app.security.archive_limits import (
    ArchiveSafetyError,
    MAX_ARCHIVE_ITEMS,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    MAX_COMPRESSION_RATIO,
    inspect_7z,
    inspect_zip,
)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_EXTRACTED_CHARS = 50_000

TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".html",
    ".htm",
    ".svg",
    ".js",
    ".ps1",
    ".vbs",
    ".bat",
    ".cmd",
}
IDENTIFIED_ONLY_EXTENSIONS = {
    ".lnk",
    ".iso",
}
SUPPORTED_EXTENSIONS = (
    TEXT_EXTENSIONS
    | IMAGE_EXTENSIONS
    | IDENTIFIED_ONLY_EXTENSIONS
    | {
        ".eml",
        ".pdf",
        ".docx",
        ".docm",
        ".pptx",
        ".pptm",
        ".xlsx",
        ".xlsm",
        ".zip",
        ".7z",
    }
)
BINARY_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".docm",
    ".pptx",
    ".pptm",
    ".xlsx",
    ".xlsm",
    ".zip",
    ".7z",
    ".lnk",
    ".iso",
} | IMAGE_EXTENSIONS


class FileReaderError(ValueError):
    def __init__(
        self,
        message: str,
        status_code: int = 400,
    ):
        super().__init__(message)
        self.status_code = status_code


def _truncate(
    text: str,
) -> tuple[str, bool]:
    text = text.strip()

    if len(text) <= MAX_EXTRACTED_CHARS:
        return text, False

    return (
        text[:MAX_EXTRACTED_CHARS],
        True,
    )


def _decode_text(data: bytes) -> str:
    return data.decode(
        "utf-8-sig",
        errors="replace",
    )


def _inspect_zip(
    data: bytes,
) -> list[zipfile.ZipInfo]:
    try:
        return inspect_zip(data)
    except ArchiveSafetyError as exc:
        raise FileReaderError(
            str(exc),
            413,
        ) from exc


def _inspect_7z(data: bytes) -> list:
    try:
        return inspect_7z(data)
    except ArchiveSafetyError as exc:
        raise FileReaderError(
            str(exc),
            413,
        ) from exc
    except Exception as exc:
        raise FileReaderError(
            "Could not safely inspect 7z archive.",
            422,
        ) from exc


def _looks_like_lnk(
    data: bytes,
) -> bool:
    shell_link_clsid = (
        b"\x4c\x00\x00\x00"
        b"\x01\x14\x02\x00"
        b"\x00\x00\x00\x00"
        b"\xc0\x00\x00\x00"
        b"\x00\x00\x00\x46"
    )
    return data.startswith(
        shell_link_clsid
    )


def _looks_like_iso(
    data: bytes,
) -> bool:
    return (
        len(data) > 32774
        and data[
            32769:32774
        ] == b"CD001"
    )


def _detect_type(
    data: bytes,
) -> str:
    if data.startswith(b"%PDF-"):
        return ".pdf"

    if data.startswith(b"MZ"):
        return ".exe"

    if data.startswith(
        b"\x7fELF"
    ):
        return "elf"

    if data.startswith(
        b"\xd0\xcf\x11\xe0"
        b"\xa1\xb1\x1a\xe1"
    ):
        return "ole"

    if _looks_like_lnk(data):
        return ".lnk"

    if _looks_like_iso(data):
        return ".iso"

    if data.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        return ".png"

    if data.startswith(
        b"\xff\xd8\xff"
    ):
        return ".jpg"

    if data.startswith(
        (
            b"GIF87a",
            b"GIF89a",
        )
    ):
        return ".gif"

    if data.startswith(b"BM"):
        return ".bmp"

    if (
        len(data) >= 12
        and data[:4] == b"RIFF"
        and data[8:12] == b"WEBP"
    ):
        return ".webp"

    if data.startswith(
        b"7z\xbc\xaf'\x1c"
    ):
        _inspect_7z(data)
        return ".7z"

    if zipfile.is_zipfile(
        BytesIO(data)
    ):
        infos = _inspect_zip(data)
        names = [
            info.filename
            for info in infos
        ]
        content_types = ""

        try:
            with zipfile.ZipFile(
                BytesIO(data)
            ) as archive:
                content_types = archive.read(
                    "[Content_Types].xml"
                ).decode(
                    "utf-8",
                    errors="ignore",
                ).lower()
        except (
            KeyError,
            zipfile.BadZipFile,
        ):
            pass

        macro_enabled = (
            "macroenabled"
            in content_types
        )

        if any(
            name.startswith("word/")
            for name in names
        ):
            return (
                ".docm"
                if macro_enabled
                else ".docx"
            )

        if any(
            name.startswith("ppt/")
            for name in names
        ):
            return (
                ".pptm"
                if macro_enabled
                else ".pptx"
            )

        if any(
            name.startswith("xl/")
            for name in names
        ):
            return (
                ".xlsm"
                if macro_enabled
                else ".xlsx"
            )

        return ".zip"

    if b"\x00" in data[:8192]:
        return "binary"

    return "text"


def _read_uploaded_file(
    filename: str,
    content_type: str | None,
    data: bytes,
    depth: int = 0,
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
    expected_detected = (
        equivalent_types.get(
            extension,
            extension,
        )
    )

    if (
        extension in BINARY_EXTENSIONS
        and detected_type
        != expected_detected
    ):
        raise FileReaderError(
            "The file content does not "
            "match its extension.",
            415,
        )

    if (
        extension
        in TEXT_EXTENSIONS
        | {".eml"}
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
    file_analysis["qr"] = (
        qr_analysis
    )
    file_analysis["urls"] = list(
        dict.fromkeys(
            file_analysis.get(
                "urls",
                [],
            )
            + qr_analysis.get(
                "urls",
                [],
            )
        )
    )

    readers = {
        ".pdf": parse_pdf,
        ".docx": parse_word,
        ".docm": (
            lambda payload:
            parse_macro_office(
                payload,
                ".docm",
            )
        ),
        ".pptx": parse_powerpoint,
        ".pptm": (
            lambda payload:
            parse_macro_office(
                payload,
                ".pptm",
            )
        ),
        ".xlsx": parse_excel,
        ".xlsm": (
            lambda payload:
            parse_macro_office(
                payload,
                ".xlsm",
            )
        ),
        ".zip": parse_archive,
        ".7z": parse_7z_archive,
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

        elif extension in (
            IDENTIFIED_ONLY_EXTENSIONS
        ):
            text = (
                "Static identification only: "
                f"{extension} artifact."
            )
            parser = "identified_only"

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
            nested, nested_text = (
                analyze_email_attachments(
                    email_result.get(
                        "attachment_payloads",
                        [],
                    ),
                    email_analysis.get(
                        "attachments",
                        [],
                    ),
                    depth=depth,
                    read_file=(
                        _read_uploaded_file
                    ),
                )
            )

            if nested:
                file_analysis[
                    "nested_artifacts"
                ] = nested

                nested_urls = []

                for artifact in nested:
                    nested_urls.extend(
                        artifact[
                            "file_analysis"
                        ].get(
                            "urls",
                            [],
                        )
                    )

                file_analysis[
                    "urls"
                ] = list(
                    dict.fromkeys(
                        file_analysis.get(
                            "urls",
                            [],
                        )
                        + nested_urls
                    )
                )

            if nested_text:
                text = (
                    text
                    + "\n\n"
                    + "\n\n".join(
                        nested_text
                    )
                )

            parser = "eml"

        else:
            text = readers[
                extension
            ](data)
            parser = (
                extension.lstrip(".")
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


def read_uploaded_file(
    filename: str,
    content_type: str | None,
    data: bytes,
) -> dict:
    return _read_uploaded_file(
        filename,
        content_type,
        data,
        0,
    )

from __future__ import annotations

import time
import zipfile
from io import BytesIO

import py7zr

MAX_ARCHIVE_ITEMS = 500
MAX_ARCHIVE_UNCOMPRESSED_BYTES = (
    50 * 1024 * 1024
)
MAX_COMPRESSION_RATIO = 100
MAX_ARCHIVE_INSPECTION_SECONDS = 3.0


class ArchiveSafetyError(ValueError):
    pass


def _validate_sizes(
    entries: list[tuple[int, int]],
    started: float,
) -> None:
    if len(entries) > MAX_ARCHIVE_ITEMS:
        raise ArchiveSafetyError(
            "Archive contains too many items "
            f"(maximum {MAX_ARCHIVE_ITEMS})."
        )

    total = sum(
        uncompressed
        for uncompressed, _ in entries
    )

    if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        raise ArchiveSafetyError(
            "Archive expands beyond the safe "
            "processing limit."
        )

    for uncompressed, compressed in entries:
        ratio = (
            uncompressed
            / max(compressed, 1)
        )

        if (
            ratio > MAX_COMPRESSION_RATIO
            and uncompressed > 1024 * 1024
        ):
            raise ArchiveSafetyError(
                "Archive has an unsafe "
                "compression ratio."
            )

    if (
        time.monotonic() - started
        > MAX_ARCHIVE_INSPECTION_SECONDS
    ):
        raise ArchiveSafetyError(
            "Archive inspection exceeded the "
            "safe processing time."
        )


def inspect_zip(
    data: bytes,
) -> list[zipfile.ZipInfo]:
    started = time.monotonic()

    with zipfile.ZipFile(
        BytesIO(data)
    ) as archive:
        infos = archive.infolist()

    _validate_sizes(
        [
            (
                int(info.file_size),
                int(info.compress_size),
            )
            for info in infos
        ],
        started,
    )
    return infos


def inspect_7z(data: bytes) -> list:
    started = time.monotonic()

    with py7zr.SevenZipFile(
        BytesIO(data),
        mode="r",
    ) as archive:
        infos = archive.list()

    _validate_sizes(
        [
            (
                int(
                    getattr(
                        info,
                        "uncompressed",
                        0,
                    )
                    or 0
                ),
                int(
                    getattr(
                        info,
                        "compressed",
                        0,
                    )
                    or 0
                ),
            )
            for info in infos
        ],
        started,
    )
    return infos

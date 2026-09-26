from io import BytesIO
from zipfile import (
    ZIP_DEFLATED,
    ZIP_STORED,
    ZipFile,
)

import pytest

from app.parsers.file_reader import (
    FileReaderError,
    MAX_ARCHIVE_ITEMS,
    read_uploaded_file,
)


def test_rejects_archive_with_too_many_items():
    buffer = BytesIO()

    with ZipFile(
        buffer,
        "w",
        compression=ZIP_STORED,
    ) as archive:
        for index in range(
            MAX_ARCHIVE_ITEMS + 1
        ):
            archive.writestr(
                f"item-{index}.txt",
                "",
            )

    with pytest.raises(
        FileReaderError
    ) as exc:
        read_uploaded_file(
            "many.zip",
            "application/zip",
            buffer.getvalue(),
        )

    assert exc.value.status_code == 413


def test_rejects_unsafe_compression_ratio():
    buffer = BytesIO()

    with ZipFile(
        buffer,
        "w",
        compression=ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "large.txt",
            b"A" * (2 * 1024 * 1024),
        )

    with pytest.raises(
        FileReaderError
    ) as exc:
        read_uploaded_file(
            "compressed.zip",
            "application/zip",
            buffer.getvalue(),
        )

    assert exc.value.status_code == 413


def test_rejects_corrupt_zip_content():
    with pytest.raises(
        FileReaderError
    ) as exc:
        read_uploaded_file(
            "broken.zip",
            "application/zip",
            b"PK-not-a-real-archive",
        )

    assert exc.value.status_code == 415

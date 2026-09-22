import zipfile
from io import BytesIO

import py7zr


def parse_archive(data: bytes) -> str:
    with zipfile.ZipFile(
        BytesIO(data)
    ) as archive:
        names = archive.namelist()

    return (
        "Archive contents:\n"
        + "\n".join(names)
    )


def parse_7z_archive(data: bytes) -> str:
    with py7zr.SevenZipFile(
        BytesIO(data),
        mode="r",
    ) as archive:
        names = [
            info.filename
            for info in archive.list()
        ]

    return (
        "Archive contents:\n"
        + "\n".join(names)
    )

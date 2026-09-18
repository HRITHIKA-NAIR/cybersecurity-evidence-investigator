import zipfile
from io import BytesIO


def parse_archive(data: bytes) -> str:
    with zipfile.ZipFile(
        BytesIO(data)
    ) as archive:
        names = archive.namelist()

    return (
        "Archive contents:\n"
        + "\n".join(names)
    )

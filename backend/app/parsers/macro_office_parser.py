from __future__ import annotations

import zipfile
from io import BytesIO
from xml.etree import ElementTree


def _xml_text(
    payload: bytes,
    tags: set[str],
) -> list[str]:
    try:
        root = ElementTree.fromstring(
            payload
        )
    except ElementTree.ParseError:
        return []

    values = []

    for element in root.iter():
        local = element.tag.rsplit(
            "}",
            1,
        )[-1]

        if (
            local in tags
            and element.text
            and element.text.strip()
        ):
            values.append(
                element.text.strip()
            )

    return values


def parse_macro_office(
    data: bytes,
    extension: str,
) -> str:
    with zipfile.ZipFile(
        BytesIO(data)
    ) as archive:
        names = archive.namelist()
        parts = []

        if extension == ".docm":
            targets = [
                name
                for name in names
                if name
                == "word/document.xml"
            ]
            tags = {"t"}

        elif extension == ".pptm":
            targets = sorted(
                name
                for name in names
                if (
                    name.startswith(
                        "ppt/slides/slide"
                    )
                    and name.endswith(
                        ".xml"
                    )
                )
            )
            tags = {"t"}

        elif extension == ".xlsm":
            targets = [
                name
                for name in names
                if (
                    name
                    == "xl/sharedStrings.xml"
                    or (
                        name.startswith(
                            "xl/worksheets/sheet"
                        )
                        and name.endswith(
                            ".xml"
                        )
                    )
                )
            ]
            tags = {
                "t",
                "v",
                "f",
            }

        else:
            return ""

        for name in targets:
            values = _xml_text(
                archive.read(name),
                tags,
            )

            if values:
                parts.append(
                    f"{name}\n"
                    + "\n".join(values)
                )

    return "\n\n".join(parts)

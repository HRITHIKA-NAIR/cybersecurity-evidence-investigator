from app.parsers.file_reader import (
    read_uploaded_file,
)


def test_identifies_lnk_without_execution():
    data = (
        b"\x4c\x00\x00\x00"
        b"\x01\x14\x02\x00"
        b"\x00\x00\x00\x00"
        b"\xc0\x00\x00\x00"
        b"\x00\x00\x00\x46"
        + b"\x00" * 64
    )

    result = read_uploaded_file(
        "shortcut.lnk",
        "application/octet-stream",
        data,
    )

    assert (
        result["file_info"][
            "detected_type"
        ]
        == ".lnk"
    )
    assert (
        result["file_info"]["parser"]
        == "identified_only"
    )
    assert (
        result["file_analysis"][
            "executed"
        ]
        is False
    )


def test_identifies_iso_without_mounting():
    data = bytearray(
        b"\x00" * 33000
    )
    data[32769:32774] = b"CD001"

    result = read_uploaded_file(
        "disk.iso",
        (
            "application/"
            "x-iso9660-image"
        ),
        bytes(data),
    )

    assert (
        result["file_info"][
            "detected_type"
        ]
        == ".iso"
    )

    attack_types = {
        finding["attack_type"]
        for finding in result[
            "file_analysis"
        ]["findings"]
    }

    assert (
        "Disk Image Identified"
        in attack_types
    )

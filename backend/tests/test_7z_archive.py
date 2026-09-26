import py7zr

from app.parsers.file_reader import (
    read_uploaded_file,
)


def test_reads_7z_without_executing_contents(
    tmp_path,
):
    script = tmp_path / "run.ps1"
    script.write_text(
        "Write-Host test",
        encoding="utf-8",
    )
    archive_path = tmp_path / "sample.7z"

    with py7zr.SevenZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.write(
            script,
            arcname="run.ps1",
        )

    result = read_uploaded_file(
        "sample.7z",
        "application/x-7z-compressed",
        archive_path.read_bytes(),
    )

    assert (
        result["file_info"][
            "detected_type"
        ]
        == ".7z"
    )
    assert "run.ps1" in result["content"]

    attack_types = {
        finding["attack_type"]
        for finding in result[
            "file_analysis"
        ]["findings"]
    }

    assert (
        "Executable or Script in Archive"
        in attack_types
    )
    assert (
        result["file_analysis"][
            "executed"
        ]
        is False
    )

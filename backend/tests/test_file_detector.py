from io import BytesIO
from zipfile import ZipFile

from app.detectors.file_detector import analyze_file


def _zip(entries: dict[str, bytes | str]) -> bytes:
    buffer = BytesIO()

    with ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)

    return buffer.getvalue()


def _types(findings):
    return {
        finding["attack_type"]
        for finding in findings
    }


def test_detects_double_extension():
    data = _zip({"note.txt": "hello"})

    result = analyze_file(
        "invoice.pdf.zip",
        ".zip",
        "application/zip",
        ".zip",
        data,
    )

    assert "Double Extension" in _types(
        result["findings"]
    )


def test_detects_hidden_extension_style_repeat():
    data = _zip({"note.txt": "hello"})

    result = analyze_file(
        "invoice.pdf.zip.zip",
        ".zip",
        "application/zip",
        ".zip",
        data,
    )

    assert "Double Extension" in _types(
        result["findings"]
    )


def test_detects_double_extension_inside_archive():
    data = _zip(
        {
            "invoice.pdf.ps1": "Write-Host test",
        }
    )

    result = analyze_file(
        "archive.zip",
        ".zip",
        "application/zip",
        ".zip",
        data,
    )

    types = _types(result["findings"])

    assert "Double Extension" in types
    assert "Executable or Script in Archive" in types


def test_detects_bidirectional_unicode_control():
    data = _zip({"note.txt": "hello"})

    result = analyze_file(
        "invoice\u202efdp.zip",
        ".zip",
        "application/zip",
        ".zip",
        data,
    )

    assert (
        "Bidirectional Unicode Control"
        in _types(result["findings"])
    )


def test_detects_declared_mime_mismatch():
    result = analyze_file(
        "report.pdf",
        ".pdf",
        "text/plain",
        ".pdf",
        b"%PDF-1.4\n%%EOF",
    )

    assert "Declared MIME Mismatch" in _types(
        result["findings"]
    )


def test_inspects_office_package_structure():
    relationships = """<?xml version="1.0"?>
    <Relationships
      xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship
        Id="rId1"
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
        Target="https://example.test/template.dotm"
        TargetMode="External"/>
    </Relationships>
    """

    data = _zip(
        {
            "word/document.xml": "<document/>",
            "word/vbaProject.bin": b"macro",
            "word/embeddings/oleObject1.bin": b"ole",
            "word/_rels/document.xml.rels": relationships,
        }
    )

    result = analyze_file(
        "report.docx",
        ".docx",
        (
            "application/vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
        ),
        ".docx",
        data,
    )

    types = _types(result["findings"])

    assert "VBA Macro Project Present" in types
    assert "Embedded Object Present" in types
    assert "External Office Relationship" in types
    assert "External Template Relationship" in types
    assert (
        "https://example.test/template.dotm"
        in result["urls"]
    )


def test_detects_pdf_active_content_and_url():
    data = (
        b"%PDF-1.4\n"
        b"1 0 obj << /OpenAction 2 0 R "
        b"/JavaScript (app.alert('x')) "
        b"/URI (https://example.test/login) >>\n"
        b"endobj\n%%EOF"
    )

    result = analyze_file(
        "document.pdf",
        ".pdf",
        "application/pdf",
        ".pdf",
        data,
    )

    types = _types(result["findings"])

    assert "PDF JavaScript" in types
    assert "PDF Open Action" in types
    assert (
        "https://example.test/login"
        in result["urls"]
    )


def test_detects_html_credential_and_redirect_indicators():
    data = b"""
    <html>
      <meta http-equiv="refresh" content="0;url=https://example.test">
      <script>window.location='https://example.test/login';</script>
      <form action="https://example.test/login">
        <input type="password">
      </form>
    </html>
    """

    result = analyze_file(
        "login.html",
        ".html",
        "text/html",
        "text",
        data,
    )

    types = _types(result["findings"])

    assert "HTML Script Content" in types
    assert "Password Input Form" in types
    assert "Meta Refresh Redirect" in types
    assert "Scripted Navigation" in types


def test_detects_svg_script_and_external_url():
    data = b"""
    <svg xmlns="http://www.w3.org/2000/svg">
      <script>alert(1)</script>
      <a href="https://example.test/path">link</a>
    </svg>
    """

    result = analyze_file(
        "image.svg",
        ".svg",
        "image/svg+xml",
        "text",
        data,
    )

    assert "SVG Script Content" in _types(
        result["findings"]
    )
    assert (
        "https://example.test/path"
        in result["urls"]
    )


def test_detects_executable_and_path_traversal_in_zip():
    data = _zip(
        {
            "invoice.pdf": "safe text",
            "run.ps1": "Write-Host test",
            "../outside.txt": "test",
        }
    )

    result = analyze_file(
        "archive.zip",
        ".zip",
        "application/zip",
        ".zip",
        data,
    )

    types = _types(result["findings"])

    assert "Executable or Script in Archive" in types
    assert "Archive Path Traversal Name" in types


def test_safe_plain_text_has_no_static_findings():
    result = analyze_file(
        "note.txt",
        ".txt",
        "text/plain",
        "text",
        b"ordinary text",
    )

    assert result["findings"] == []
    assert result["highest_severity"] == "Info"
    assert result["executed"] is False

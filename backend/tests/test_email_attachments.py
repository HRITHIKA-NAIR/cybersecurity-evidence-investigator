from email.message import EmailMessage

from app.parsers.file_reader import (
    read_uploaded_file,
)


def test_routes_supported_email_attachment_through_file_analysis():
    message = EmailMessage()
    message["From"] = (
        "Sender <sender@example.com>"
    )
    message["To"] = "user@example.org"
    message["Subject"] = "Attached page"
    message.set_content(
        "Please review the attachment."
    )
    message.add_attachment(
        (
            b"<html><form>"
            b"<input type='password'>"
            b"</form>"
            b"<a href='https://example.test/login'>"
            b"Open</a></html>"
        ),
        maintype="text",
        subtype="html",
        filename="landing.html",
    )

    result = read_uploaded_file(
        "message.eml",
        "message/rfc822",
        message.as_bytes(),
    )

    attachment = result[
        "email_analysis"
    ]["attachments"][0]

    assert (
        attachment["analysis_status"]
        == "analyzed"
    )
    assert attachment["sha256"]

    nested = result[
        "file_analysis"
    ]["nested_artifacts"][0]

    attack_types = {
        finding["attack_type"]
        for finding in nested[
            "file_analysis"
        ]["findings"]
    }

    assert (
        "Password Input Form"
        in attack_types
    )
    assert (
        "https://example.test/login"
        in result["content"]
    )

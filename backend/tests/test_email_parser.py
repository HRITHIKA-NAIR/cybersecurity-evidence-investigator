from app.parsers.email_parser import parse_email


def test_parses_claimed_sender_and_core_headers():
    data = (
        b"From: Payroll <payroll@company.test>\r\n"
        b"Reply-To: payroll@company.test\r\n"
        b"Return-Path: <bounce@company.test>\r\n"
        b"Subject: Monthly payroll\r\n"
        b"Message-ID: <abc123@company.test>\r\n"
        b"Date: Fri, 18 Sep 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Hello"
    )

    result = parse_email(data)["forensics"]

    assert result["claimed_sender_name"] == "Payroll"
    assert result["sender_address"] == "payroll@company.test"
    assert result["sender_domain"] == "company.test"
    assert result["reply_to"] == "payroll@company.test"
    assert result["message_id"] == "<abc123@company.test>"


def test_detects_reply_to_domain_mismatch():
    data = (
        b"From: Billing <billing@company.test>\r\n"
        b"Reply-To: payment@other.test\r\n"
        b"\r\n"
        b"Hello"
    )

    result = parse_email(data)["forensics"]

    assert (
        "Reply-To domain differs from the claimed sender domain."
        in result["warnings"]
    )


def test_uses_earliest_public_received_hop():
    data = (
        b"From: sender@example.test\r\n"
        b"Received: from relay [1.1.1.1] by mx; "
        b"Fri, 18 Sep 2026 10:02:00 +0000\r\n"
        b"Received: from origin [8.8.8.8] by relay; "
        b"Fri, 18 Sep 2026 10:01:00 +0000\r\n"
        b"\r\n"
        b"Hello"
    )

    result = parse_email(data)["forensics"]

    assert result["originating_ip"] == "8.8.8.8"
    assert result["origin_source"] == "Received"
    assert (
        result["earliest_received_time"]
        == "2026-09-18T10:01:00+00:00"
    )


def test_ignores_private_received_ips():
    data = (
        b"From: sender@example.test\r\n"
        b"Received: from internal [192.168.1.5] by mx; "
        b"Fri, 18 Sep 2026 10:01:00 +0000\r\n"
        b"\r\n"
        b"Hello"
    )

    result = parse_email(data)["forensics"]

    assert result["originating_ip"] is None


def test_parses_header_reported_authentication():
    data = (
        b"From: sender@example.test\r\n"
        b"Authentication-Results: mx.example; "
        b"spf=pass smtp.mailfrom=example.test; "
        b"dkim=fail header.d=example.test; "
        b"dmarc=pass header.from=example.test\r\n"
        b"\r\n"
        b"Hello"
    )

    result = parse_email(data)["forensics"]
    authentication = result["authentication"]

    assert authentication["spf"] == "pass"
    assert authentication["dkim"] == "fail"
    assert authentication["dmarc"] == "pass"
    assert authentication["independently_verified"] is False
    assert any(
        "DKIM result is fail" in warning
        for warning in result["warnings"]
    )


def test_handles_malformed_date_without_failure():
    data = (
        b"From: sender@example.test\r\n"
        b"Date: not-a-real-date\r\n"
        b"\r\n"
        b"Hello"
    )

    result = parse_email(data)["forensics"]

    assert result["claimed_send_time"] is None


def test_lists_attachments_without_executing_them():
    data = (
        b"From: sender@example.test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=abc\r\n"
        b"\r\n"
        b"--abc\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Hello\r\n"
        b"--abc\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=invoice.pdf\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQ=\r\n"
        b"--abc--\r\n"
    )

    result = parse_email(data)["forensics"]

    assert len(result["attachments"]) == 1
    assert result["attachments"][0]["filename"] == "invoice.pdf"
    assert (
        result["attachments"][0]["content_type"]
        == "application/pdf"
    )

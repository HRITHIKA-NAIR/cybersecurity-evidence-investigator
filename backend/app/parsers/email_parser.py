from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

_IPV4 = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
)
_BRACKETED_IP = re.compile(r"\[([0-9A-Fa-f:.]+)\]")


def _address_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None

    return address.rsplit("@", 1)[1].strip().lower() or None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _public_ips(value: str) -> list[str]:
    candidates = _IPV4.findall(value)
    candidates.extend(_BRACKETED_IP.findall(value))

    result = []

    for candidate in candidates:
        candidate = candidate.removeprefix("IPv6:")

        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        if ip.is_global:
            normalized = str(ip)

            if normalized not in result:
                result.append(normalized)

    return result


def _received_time(value: str) -> datetime | None:
    if ";" not in value:
        return None

    return _parse_datetime(
        value.rsplit(";", 1)[1].strip()
    )


def _auth_status(message, mechanism: str) -> str:
    pattern = re.compile(
        rf"\b{re.escape(mechanism)}\s*=\s*"
        r"([a-zA-Z0-9_-]+)",
        re.IGNORECASE,
    )

    for header in message.get_all(
        "Authentication-Results",
        [],
    ):
        match = pattern.search(str(header))

        if match:
            return match.group(1).lower()

    if mechanism == "spf":
        for header in message.get_all(
            "Received-SPF",
            [],
        ):
            match = re.match(
                r"\s*([a-zA-Z0-9_-]+)",
                str(header),
            )

            if match:
                return match.group(1).lower()

    return "not_reported"


def parse_email(data: bytes) -> dict:
    message = BytesParser(
        policy=policy.default
    ).parsebytes(data)

    claimed_name, sender_address = parseaddr(
        str(message.get("From", ""))
    )
    _, reply_to = parseaddr(
        str(message.get("Reply-To", ""))
    )
    _, return_path = parseaddr(
        str(message.get("Return-Path", ""))
    )

    sender_domain = _address_domain(sender_address)
    reply_to_domain = _address_domain(reply_to)
    return_path_domain = _address_domain(return_path)

    claimed_time = _parse_datetime(
        str(message.get("Date", "")) or None
    )

    received_headers = [
        str(value)
        for value in message.get_all(
            "Received",
            [],
        )
    ]

    earliest_received_time = None
    originating_ip = None
    origin_source = None

    for header in reversed(received_headers):
        if earliest_received_time is None:
            earliest_received_time = _received_time(
                header
            )

        if originating_ip is None:
            public_ips = _public_ips(header)

            if public_ips:
                originating_ip = public_ips[0]
                origin_source = "Received"

    if originating_ip is None:
        for header in message.get_all(
            "X-Originating-IP",
            [],
        ):
            public_ips = _public_ips(str(header))

            if public_ips:
                originating_ip = public_ips[0]
                origin_source = "X-Originating-IP"
                break

    authentication = {
        "spf": _auth_status(message, "spf"),
        "dkim": _auth_status(message, "dkim"),
        "dmarc": _auth_status(message, "dmarc"),
        "source": "message_headers",
        "independently_verified": False,
    }

    attachments = []
    attachment_payloads = []

    for part in message.iter_attachments():
        payload = (
            part.get_payload(
                decode=True
            )
            or b""
        )
        metadata = {
            "filename": part.get_filename(),
            "content_type": (
                part.get_content_type()
            ),
            "size_bytes": len(payload),
        }
        attachments.append(metadata)
        attachment_payloads.append(
            {
                **metadata,
                "data": payload,
            }
        )

    warnings = []

    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):
        warnings.append(
            "Reply-To domain differs from the "
            "claimed sender domain."
        )

    if (
        sender_domain
        and return_path_domain
        and sender_domain != return_path_domain
    ):
        warnings.append(
            "Return-Path domain differs from the "
            "claimed sender domain."
        )

    for mechanism in (
        "spf",
        "dkim",
        "dmarc",
    ):
        status = authentication[mechanism]

        if status in {
            "fail",
            "softfail",
            "temperror",
            "permerror",
        }:
            warnings.append(
                "Header-reported "
                f"{mechanism.upper()} result is "
                f"{status}."
            )

    if (
        claimed_time
        and earliest_received_time
        and claimed_time.tzinfo
        and earliest_received_time.tzinfo
        and (
            claimed_time - earliest_received_time
        ).total_seconds()
        > 86400
    ):
        warnings.append(
            "Claimed send time is more than "
            "24 hours after the earliest server "
            "Received timestamp."
        )

    body = message.get_body(
        preferencelist=("plain", "html")
    )
    body_text = ""

    if body:
        try:
            body_text = body.get_content()
        except (
            KeyError,
            LookupError,
            UnicodeDecodeError,
        ):
            body_text = ""

    content_parts = [
        f"From: {message.get('From', '')}",
        f"Reply-To: {message.get('Reply-To', '')}",
        f"Return-Path: {message.get('Return-Path', '')}",
        f"Subject: {message.get('Subject', '')}",
        f"Date: {message.get('Date', '')}",
        body_text,
    ]

    return {
        "content": "\n".join(
            str(part)
            for part in content_parts
            if str(part).strip()
        ),
        "attachment_payloads": (
            attachment_payloads
        ),
        "forensics": {
            "claimed_sender_name": (
                claimed_name or None
            ),
            "sender_address": (
                sender_address or None
            ),
            "sender_domain": sender_domain,
            "reply_to": reply_to or None,
            "reply_to_domain": (
                reply_to_domain
            ),
            "return_path": (
                return_path or None
            ),
            "return_path_domain": (
                return_path_domain
            ),
            "subject": (
                str(
                    message.get(
                        "Subject",
                        "",
                    )
                )
                or None
            ),
            "message_id": (
                str(
                    message.get(
                        "Message-ID",
                        "",
                    )
                )
                or None
            ),
            "claimed_send_time": _iso(
                claimed_time
            ),
            "earliest_received_time": _iso(
                earliest_received_time
            ),
            "received_hop_count": len(
                received_headers
            ),
            "originating_ip": originating_ip,
            "origin_source": origin_source,
            "authentication": authentication,
            "attachments": attachments,
            "warnings": warnings,
        },
    }

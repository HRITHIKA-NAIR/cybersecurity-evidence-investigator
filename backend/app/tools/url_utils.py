from __future__ import annotations

from urllib.parse import (
    urlsplit,
    urlunsplit,
)

MAX_URL_LENGTH = 4096


def normalize_http_url(
    url: str,
) -> tuple[str, str]:
    value = (url or "").strip()

    if not value:
        raise ValueError("URL is empty.")

    if len(value) > MAX_URL_LENGTH:
        raise ValueError(
            "URL exceeds the safe processing limit."
        )

    if any(
        ord(char) < 32
        or ord(char) == 127
        for char in value
    ):
        raise ValueError(
            "URL contains control characters."
        )

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()

    if scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            "URL does not contain a hostname."
        )

    hostname = (
        hostname.rstrip(".").lower()
    )

    try:
        hostname = (
            hostname
            .encode("idna")
            .decode("ascii")
        )
    except UnicodeError as exc:
        raise ValueError(
            "URL hostname is not valid IDNA."
        ) from exc

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "URL contains an invalid port."
        ) from exc

    host_part = (
        f"[{hostname}]"
        if ":" in hostname
        else hostname
    )
    userinfo = ""

    if parsed.username is not None:
        userinfo = parsed.username

        if parsed.password is not None:
            userinfo += (
                ":" + parsed.password
            )

        userinfo += "@"

    netloc = (
        userinfo
        + host_part
        + (
            f":{port}"
            if port is not None
            else ""
        )
    )

    normalized = urlunsplit(
        (
            scheme,
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

    return normalized, hostname

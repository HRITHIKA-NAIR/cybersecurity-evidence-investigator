from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def normalize_http_url(url: str) -> tuple[str, str]:
    value = (url or "").strip()

    if not value:
        raise ValueError("URL is empty.")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("URL does not contain a hostname.")

    normalized = urlunsplit(
        (
            scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

    return normalized, hostname.rstrip(".").lower()

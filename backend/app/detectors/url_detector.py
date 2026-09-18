from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

import tldextract

from app.tools.url_utils import normalize_http_url

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
ENCODED_TOKEN = re.compile(r"%[0-9a-fA-F]{2}")
LOOKALIKE_TOKEN = re.compile(r"(?:0|1|rn|vv|-{2,})", re.I)


def _registered_domain(hostname: str) -> tuple[str, str]:
    try:
        ipaddress.ip_address(hostname)
        return "", ""
    except ValueError:
        pass

    extracted = _EXTRACT(hostname)

    if not extracted.domain:
        return "", ""

    registered = extracted.domain

    if extracted.suffix:
        registered = f"{extracted.domain}.{extracted.suffix}"

    return registered, extracted.subdomain


def _apparent_subdomain_domain(
    subdomain: str,
    registered_domain: str,
) -> str | None:
    labels = [label for label in subdomain.split(".") if label]

    for index in range(len(labels) - 1):
        candidate = f"{labels[index]}.{labels[index + 1]}"
        extracted = _EXTRACT(candidate)

        if not extracted.domain or not extracted.suffix:
            continue

        apparent = f"{extracted.domain}.{extracted.suffix}"

        if apparent != registered_domain:
            return apparent

    return None


def _finding(kind: str, message: str) -> dict:
    return {"type": kind, "message": message}


def analyze_url(url: str) -> dict:
    findings = []

    try:
        normalized, hostname = normalize_http_url(url)
    except ValueError as exc:
        return {
            "url": url,
            "normalized_url": None,
            "hostname": "",
            "scheme": "",
            "registered_domain": "",
            "subdomain": "",
            "findings": [_finding("warning", str(exc))],
        }

    parsed = urlsplit(normalized)
    registered_domain, subdomain = _registered_domain(hostname)

    findings.append(
        _finding(
            "positive" if parsed.scheme == "https" else "warning",
            "URL uses HTTPS"
            if parsed.scheme == "https"
            else "URL does not use HTTPS",
        )
    )

    try:
        ipaddress.ip_address(hostname)
        findings.append(
            _finding(
                "suspicious",
                "URL uses an IP address instead of a domain name",
            )
        )
    except ValueError:
        pass

    if len(normalized) > 100:
        findings.append(_finding("warning", "URL is unusually long"))

    subdomain_labels = [
        label for label in subdomain.split(".") if label
    ]
    if len(subdomain_labels) >= 3:
        findings.append(
            _finding(
                "warning",
                "Domain contains many subdomain levels",
            )
        )

    if parsed.username is not None:
        findings.append(
            _finding(
                "suspicious",
                "URL contains user-info before the hostname",
            )
        )

    if any(
        label.startswith("xn--")
        for label in hostname.split(".")
    ):
        findings.append(_finding("warning", "Domain uses Punycode"))

    try:
        port = parsed.port
    except ValueError:
        port = None
        findings.append(_finding("suspicious", "URL contains an invalid port"))

    standard_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != standard_port:
        findings.append(
            _finding(
                "warning",
                f"URL uses a non-standard port ({port})",
            )
        )

    encoded_tokens = ENCODED_TOKEN.findall(normalized)
    if len(encoded_tokens) >= 2:
        findings.append(
            _finding(
                "warning",
                "URL contains multiple percent-encoded characters",
            )
        )

    if "%25" in normalized.lower():
        findings.append(
            _finding(
                "suspicious",
                "URL contains possible double encoding",
            )
        )

    decoded_once = unquote(normalized)
    if decoded_once != normalized and (
        "@" in decoded_once or "\\" in decoded_once
    ):
        findings.append(
            _finding(
                "suspicious",
                "Decoded URL reveals potentially deceptive characters",
            )
        )

    if registered_domain:
        domain_label = registered_domain.split(".", 1)[0]

        if LOOKALIKE_TOKEN.search(domain_label):
            findings.append(
                _finding(
                    "warning",
                    (
                        "Registered domain contains lookalike-style "
                        "character patterns consistent with a possible "
                        "typosquat"
                    ),
                )
            )

        apparent = _apparent_subdomain_domain(
            subdomain,
            registered_domain,
        )
        if apparent:
            findings.append(
                _finding(
                    "suspicious",
                    (
                        f"Subdomain contains the domain-like name {apparent} "
                        f"while the registered domain is {registered_domain}"
                    ),
                )
            )

    return {
        "url": url,
        "normalized_url": normalized,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "findings": findings,
    }

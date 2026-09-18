from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

from app.tools.url_utils import normalize_http_url

MAX_REDIRECTS = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}
CLOUD_METADATA_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "instance-data",
}
CLOUD_METADATA_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "169.254.0.0/16",
        "100.100.100.200/32",
        "168.63.129.16/32",
        "fd00:ec2::254/128",
    )
)


class UnsafeRedirectTarget(ValueError):
    pass


def _blocked_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
    ):
        return True

    return any(
        ip in network
        for network in CLOUD_METADATA_NETWORKS
    )


def _resolve_ips(hostname: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(hostname)
        return [str(literal)]
    except ValueError:
        pass

    answers = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
    )

    return list(
        dict.fromkeys(
            answer[4][0]
            for answer in answers
        )
    )


def validate_public_target(url: str) -> tuple[str, list[str]]:
    normalized, hostname = normalize_http_url(url)

    if hostname in CLOUD_METADATA_HOSTS:
        raise UnsafeRedirectTarget(
            "Cloud metadata hostname is blocked."
        )

    parsed = urlsplit(normalized)

    try:
        port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )
    except ValueError as exc:
        raise UnsafeRedirectTarget(
            "URL contains an invalid port."
        ) from exc

    try:
        addresses = _resolve_ips(
            hostname,
            port,
        )
    except socket.gaierror as exc:
        raise UnsafeRedirectTarget(
            "Hostname could not be resolved."
        ) from exc

    if not addresses:
        raise UnsafeRedirectTarget(
            "Hostname did not resolve to an IP address."
        )

    if any(
        _blocked_ip(address)
        for address in addresses
    ):
        raise UnsafeRedirectTarget(
            "Target resolves to a blocked internal or "
            "non-public address."
        )

    return normalized, addresses


def _request_once(url: str) -> dict:
    timeout = httpx.Timeout(
        6.0,
        connect=3.0,
    )

    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers={
            "User-Agent": (
                "Cybersecurity-Evidence-Investigator/2"
            )
        },
    ) as client:
        response = client.head(url)

        if response.status_code in {405, 501}:
            with client.stream(
                "GET",
                url,
            ) as streamed:
                return {
                    "status_code": streamed.status_code,
                    "location": streamed.headers.get(
                        "location"
                    ),
                    "method": "GET",
                }

        return {
            "status_code": response.status_code,
            "location": response.headers.get(
                "location"
            ),
            "method": "HEAD",
        }


def safe_follow(url: str) -> dict:
    hops = []
    current = url

    for index in range(MAX_REDIRECTS + 1):
        try:
            normalized, addresses = (
                validate_public_target(current)
            )
        except ValueError as exc:
            return {
                "status": "blocked",
                "reason": str(exc),
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }

        try:
            response = _request_once(
                normalized
            )
        except httpx.TimeoutException:
            return {
                "status": "timeout",
                "reason": "URL request timed out.",
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }
        except httpx.RequestError:
            return {
                "status": "error",
                "reason": (
                    "Could not connect to the URL."
                ),
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }

        hops.append(
            {
                "url": normalized,
                "resolved_ips": addresses,
                "status_code": response[
                    "status_code"
                ],
                "method": response[
                    "method"
                ],
            }
        )

        location = response.get(
            "location"
        )

        if (
            response["status_code"]
            not in REDIRECT_CODES
            or not location
        ):
            return {
                "status": "completed",
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }

        if index >= MAX_REDIRECTS:
            return {
                "status": "limit_reached",
                "reason": (
                    "Maximum redirect limit reached."
                ),
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }

        current = urljoin(
            normalized,
            location,
        )

    return {
        "status": "limit_reached",
        "reason": "Maximum redirect limit reached.",
        "hops": hops,
        "redirect_count": max(
            0,
            len(hops) - 1,
        ),
    }

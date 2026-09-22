from __future__ import annotations

import ipaddress
import socket
from urllib.parse import (
    urljoin,
    urlsplit,
)

import certifi
import urllib3

from app.tools.url_utils import (
    normalize_http_url,
)

MAX_REDIRECTS = 5
REDIRECT_CODES = {
    301,
    302,
    303,
    307,
    308,
}
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


class URLResolutionError(RuntimeError):
    pass


class PinnedRequestError(RuntimeError):
    pass


class PinnedTimeoutError(
    PinnedRequestError
):
    pass


def _blocked_ip(
    ip_text: str,
) -> bool:
    ip = ipaddress.ip_address(
        ip_text
    )

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
        for network
        in CLOUD_METADATA_NETWORKS
    )


def _resolve_ips(
    hostname: str,
    port: int,
) -> list[str]:
    try:
        literal = ipaddress.ip_address(
            hostname
        )
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


def validate_public_target(
    url: str,
) -> tuple[str, list[str]]:
    normalized, hostname = (
        normalize_http_url(url)
    )

    if (
        hostname
        in CLOUD_METADATA_HOSTS
    ):
        raise UnsafeRedirectTarget(
            "Cloud metadata hostname is blocked."
        )

    parsed = urlsplit(normalized)

    try:
        port = parsed.port or (
            443
            if parsed.scheme == "https"
            else 80
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
    except OSError as exc:
        raise URLResolutionError(
            "Hostname could not be resolved."
        ) from exc

    if not addresses:
        raise UnsafeRedirectTarget(
            "Hostname did not resolve to "
            "an IP address."
        )

    if any(
        _blocked_ip(address)
        for address in addresses
    ):
        raise UnsafeRedirectTarget(
            "Target resolves to a blocked "
            "internal or non-public address."
        )

    return normalized, addresses


def _host_header(
    hostname: str,
    port: int,
    scheme: str,
) -> str:
    host = (
        f"[{hostname}]"
        if ":" in hostname
        else hostname
    )
    default_port = (
        443
        if scheme == "https"
        else 80
    )

    if port != default_port:
        return f"{host}:{port}"

    return host


def _request_with_pool(
    pool,
    target: str,
    host_header: str,
) -> dict:
    headers = {
        "Host": host_header,
        "User-Agent": (
            "Cybersecurity-Evidence-Investigator/2"
        ),
    }

    response = pool.request(
        "HEAD",
        target,
        headers=headers,
        redirect=False,
        retries=False,
        preload_content=False,
    )

    try:
        if response.status not in {
            405,
            501,
        }:
            return {
                "status_code": (
                    response.status
                ),
                "location": (
                    response.headers.get(
                        "location"
                    )
                ),
                "method": "HEAD",
            }
    finally:
        response.close()

    response = pool.request(
        "GET",
        target,
        headers=headers,
        redirect=False,
        retries=False,
        preload_content=False,
    )

    try:
        return {
            "status_code": (
                response.status
            ),
            "location": (
                response.headers.get(
                    "location"
                )
            ),
            "method": "GET",
        }
    finally:
        response.close()


def _request_once(
    url: str,
    addresses: list[str],
) -> dict:
    parsed = urlsplit(url)
    hostname = parsed.hostname

    if not hostname:
        raise PinnedRequestError(
            "URL does not contain a hostname."
        )

    port = parsed.port or (
        443
        if parsed.scheme == "https"
        else 80
    )
    target = parsed.path or "/"

    if parsed.query:
        target += "?" + parsed.query

    host_header = _host_header(
        hostname,
        port,
        parsed.scheme,
    )
    timeout = urllib3.Timeout(
        connect=3.0,
        read=6.0,
    )
    last_error = None

    for address in addresses:
        pool = None

        try:
            if parsed.scheme == "https":
                pool = (
                    urllib3
                    .HTTPSConnectionPool(
                        address,
                        port=port,
                        timeout=timeout,
                        maxsize=1,
                        block=True,
                        cert_reqs=(
                            "CERT_REQUIRED"
                        ),
                        ca_certs=(
                            certifi.where()
                        ),
                        assert_hostname=(
                            hostname
                        ),
                        server_hostname=(
                            hostname
                        ),
                    )
                )
            else:
                pool = (
                    urllib3
                    .HTTPConnectionPool(
                        address,
                        port=port,
                        timeout=timeout,
                        maxsize=1,
                        block=True,
                    )
                )

            return _request_with_pool(
                pool,
                target,
                host_header,
            )

        except urllib3.exceptions.TimeoutError as exc:
            last_error = PinnedTimeoutError(
                "URL request timed out."
            )
            last_error.__cause__ = exc

        except (
            urllib3.exceptions.HTTPError,
            OSError,
            ValueError,
        ) as exc:
            last_error = PinnedRequestError(
                "Could not connect to "
                "the URL."
            )
            last_error.__cause__ = exc

        finally:
            if pool is not None:
                pool.close()

    if last_error:
        raise last_error

    raise PinnedRequestError(
        "No validated address was available."
    )


def safe_follow(url: str) -> dict:
    hops = []
    current = url

    for index in range(
        MAX_REDIRECTS + 1
    ):
        try:
            normalized, addresses = (
                validate_public_target(
                    current
                )
            )
        except URLResolutionError as exc:
            return {
                "status": "error",
                "reason": str(exc),
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }
        except ValueError as exc:
            return {
                "status": "blocked",
                "reason": str(exc),
                "blocked_url": current,
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }

        try:
            response = _request_once(
                normalized,
                addresses,
            )
        except PinnedTimeoutError:
            return {
                "status": "timeout",
                "reason": (
                    "URL request timed out."
                ),
                "hops": hops,
                "redirect_count": max(
                    0,
                    len(hops) - 1,
                ),
            }
        except PinnedRequestError:
            return {
                "status": "error",
                "reason": (
                    "Could not connect to "
                    "the URL."
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
                "resolved_ips": (
                    addresses
                ),
                "status_code": (
                    response[
                        "status_code"
                    ]
                ),
                "method": (
                    response["method"]
                ),
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
                "status": (
                    "limit_reached"
                ),
                "reason": (
                    "Maximum redirect "
                    "limit reached."
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
        "reason": (
            "Maximum redirect limit reached."
        ),
        "hops": hops,
        "redirect_count": max(
            0,
            len(hops) - 1,
        ),
    }

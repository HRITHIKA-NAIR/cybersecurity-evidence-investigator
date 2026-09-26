from __future__ import annotations

import ipaddress

from app.tools.virustotal import (
    check_domain,
    check_hash,
    check_ip,
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def gather_threat_intelligence(
    indicators: dict,
    file_info: dict | None = None,
) -> list[dict]:
    results = []
    seen = set()

    for value in indicators.get(
        "domains",
        [],
    ):
        key = (
            "ip" if _is_ip(value) else "domain",
            value,
        )

        if key in seen:
            continue

        seen.add(key)

        if key[0] == "ip":
            results.append(
                check_ip(value)
            )
        else:
            results.append(
                check_domain(value)
            )

    sha256 = (
        file_info.get("sha256")
        if file_info
        else None
    )

    if sha256:
        key = ("hash", sha256)

        if key not in seen:
            results.append(
                check_hash(sha256)
            )

    return results

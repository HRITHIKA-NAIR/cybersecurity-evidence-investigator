import os

import httpx
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
CLIENT = httpx.Client(
    base_url=BASE_URL,
    timeout=10,
    trust_env=False,
)


def _lookup(resource: str, value: str, key: str):
    base = {
        key: value,
    }

    if not API_KEY or os.getenv("ENABLE_VIRUSTOTAL", "false").lower() != "true":
        return None, {
            **base,
            "status": "unavailable",
            "message": (
                "VirusTotal lookup is disabled or not configured"
            ),
        }

    try:
        response = CLIENT.get(
            f"/{resource}/{value}",
            headers={
                "x-apikey": API_KEY,
            },
        )

        if response.status_code == 404:
            return None, {
                **base,
                "status": "unknown",
                "message": (
                    "Indicator not found "
                    "in VirusTotal"
                ),
            }

        if response.status_code == 429:
            return None, {
                **base,
                "status": "rate_limited",
                "message": (
                    "VirusTotal rate "
                    "limit reached"
                ),
            }

        response.raise_for_status()

        return (
            response.json()[
                "data"
            ]["attributes"],
            None,
        )

    except httpx.RequestError:
        return None, {
            **base,
            "status": "error",
            "message": (
                "Could not connect "
                "to VirusTotal"
            ),
        }

    except (
        httpx.HTTPStatusError,
        KeyError,
        TypeError,
    ):
        return None, {
            **base,
            "status": "error",
            "message": (
                "VirusTotal returned "
                "an error"
            ),
        }


def check_domain(domain: str):
    data, error = _lookup(
        "domains",
        domain,
        "domain",
    )

    if error:
        return error

    stats = data.get(
        "last_analysis_stats",
        {},
    )

    return {
        "domain": domain,
        "status": "success",
        "malicious": stats.get(
            "malicious",
            0,
        ),
        "suspicious": stats.get(
            "suspicious",
            0,
        ),
        "harmless": stats.get(
            "harmless",
            0,
        ),
        "undetected": stats.get(
            "undetected",
            0,
        ),
        "reputation": data.get(
            "reputation",
            0,
        ),
    }


def check_ip(ip_address: str):
    data, error = _lookup(
        "ip_addresses",
        ip_address,
        "ip",
    )

    if error:
        return error

    stats = data.get(
        "last_analysis_stats",
        {},
    )

    return {
        "ip": ip_address,
        "status": "success",
        "country": data.get(
            "country"
        ),
        "asn": data.get(
            "asn"
        ),
        "as_owner": data.get(
            "as_owner"
        ),
        "network": data.get(
            "network"
        ),
        "malicious": stats.get(
            "malicious",
            0,
        ),
        "suspicious": stats.get(
            "suspicious",
            0,
        ),
        "harmless": stats.get(
            "harmless",
            0,
        ),
        "undetected": stats.get(
            "undetected",
            0,
        ),
        "reputation": data.get(
            "reputation",
            0,
        ),
    }



def check_hash(sha256: str):
    data, error = _lookup(
        "files",
        sha256,
        "hash",
    )

    if error:
        return error

    stats = data.get(
        "last_analysis_stats",
        {},
    )

    return {
        "hash": sha256,
        "status": "success",
        "malicious": stats.get(
            "malicious",
            0,
        ),
        "suspicious": stats.get(
            "suspicious",
            0,
        ),
        "harmless": stats.get(
            "harmless",
            0,
        ),
        "undetected": stats.get(
            "undetected",
            0,
        ),
        "reputation": data.get(
            "reputation",
            0,
        ),
        "type_description": data.get(
            "type_description"
        ),
    }

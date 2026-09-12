import os

import httpx
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"


def check_domain(domain: str):
    if not API_KEY:
        return {
            "domain": domain,
            "status": "unavailable",
            "message": "VirusTotal API key is not configured",
        }

    try:
        response = httpx.get(
            f"{BASE_URL}/domains/{domain}",
            headers={"x-apikey": API_KEY},
            timeout=10,
        )

        if response.status_code == 404:
            return {
                "domain": domain,
                "status": "unknown",
                "message": "Domain not found in VirusTotal",
            }

        if response.status_code == 429:
            return {
                "domain": domain,
                "status": "rate_limited",
                "message": "VirusTotal rate limit reached",
            }

        response.raise_for_status()

        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})

        return {
            "domain": domain,
            "status": "success",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation", 0),
        }

    except httpx.RequestError:
        return {
            "domain": domain,
            "status": "error",
            "message": "Could not connect to VirusTotal",
        }

    except httpx.HTTPStatusError:
        return {
            "domain": domain,
            "status": "error",
            "message": "VirusTotal returned an error",
        }
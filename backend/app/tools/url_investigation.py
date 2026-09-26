from __future__ import annotations

from app.detectors.url_detector import analyze_url
from app.security.ssrf import safe_follow


def investigate_url(url: str) -> dict:
    result = analyze_url(url)

    if not result.get("normalized_url"):
        result["redirect_analysis"] = {
            "status": "blocked",
            "reason": "URL could not be normalized safely.",
            "hops": [],
            "redirect_count": 0,
        }
        return result

    result["redirect_analysis"] = safe_follow(
        result["normalized_url"]
    )

    return result

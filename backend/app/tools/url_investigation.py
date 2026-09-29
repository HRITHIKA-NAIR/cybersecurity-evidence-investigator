from __future__ import annotations

from app.detectors.lookalike import check_hostname
from app.detectors.url_detector import analyze_url
from app.security.ssrf import safe_follow
from app.tools.page_inspection import inspect_page


def investigate_url(url: str, *, inspect: bool = True) -> dict:
    result = analyze_url(url)

    if not result.get("normalized_url"):
        result["redirect_analysis"] = {
            "status": "blocked",
            "reason": "URL could not be normalized safely.",
            "hops": [],
            "redirect_count": 0,
        }
        return result

    hostname = result.get("hostname", "")
    known = {item["message"] for item in result["findings"]}
    for item in check_hostname(hostname):
        if item["message"] not in known:
            result["findings"].append(item)

    result["redirect_analysis"] = safe_follow(result["normalized_url"])

    # Hop-by-hop look-alike check: a redirect may land on an imitation domain.
    for hop in result["redirect_analysis"].get("hops", [])[1:]:
        for item in check_hostname(_hop_host(hop.get("url", ""))):
            message = f"Redirect destination: {item['message']}"
            if message not in known:
                known.add(message)
                result["findings"].append({"type": item["type"], "message": message})

    if inspect and result["redirect_analysis"].get("status") == "completed":
        page = inspect_page(result["normalized_url"])
        result["page_analysis"] = page
        result["findings"].extend(page.get("findings", []))
    elif inspect:
        result["page_analysis"] = {
            "status": "skipped",
            "reason": "The address could not be followed safely, so its page was not inspected.",
            "findings": [],
            "limits": [],
        }

    return result


def _hop_host(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""

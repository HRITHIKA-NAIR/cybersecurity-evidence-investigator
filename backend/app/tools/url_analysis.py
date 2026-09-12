import ipaddress
from urllib.parse import urlparse


def analyze_url(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    findings = []

    if parsed.scheme == "https":
        findings.append({
            "type": "positive",
            "message": "URL uses HTTPS"
        })
    else:
        findings.append({
            "type": "warning",
            "message": "URL does not use HTTPS"
        })

    try:
        ipaddress.ip_address(hostname)
        findings.append({
            "type": "suspicious",
            "message": "URL uses an IP address instead of a domain name"
        })
    except ValueError:
        pass

    if len(url) > 100:
        findings.append({
            "type": "warning",
            "message": "URL is unusually long"
        })

    if hostname.count(".") >= 3:
        findings.append({
            "type": "warning",
            "message": "Domain contains many subdomains"
        })

    if "@" in url:
        findings.append({
            "type": "suspicious",
            "message": "URL contains an @ symbol"
        })

    if hostname.startswith("xn--"):
        findings.append({
            "type": "warning",
            "message": "Domain uses Punycode"
        })

    return {
        "url": url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "findings": findings,
    }
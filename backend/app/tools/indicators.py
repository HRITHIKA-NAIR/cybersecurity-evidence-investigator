import re

from app.tools.url_utils import normalize_http_url


def extract_indicators(content: str):
    urls = list(
        dict.fromkeys(
            re.findall(
                r"https?://[^\s<>\"']+",
                content,
            )
        )
    )

    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        content,
    )

    domains = []

    for url in urls:
        try:
            _, domain = normalize_http_url(url)
        except ValueError:
            domain = None

        if domain and domain not in domains:
            domains.append(domain)

    for email in emails:
        domain = email.rsplit("@", 1)[1].lower()

        if domain not in domains:
            domains.append(domain)

    return {
        "urls": urls,
        "domains": domains,
        "emails": list(dict.fromkeys(emails)),
    }
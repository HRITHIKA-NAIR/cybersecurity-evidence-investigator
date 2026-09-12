import re
from urllib.parse import urlparse


def extract_indicators(content: str):
    urls = re.findall(r"https?://[^\s<>\"']+", content)

    domains = []

    for url in urls:
        domain = urlparse(url).hostname

        if domain and domain not in domains:
            domains.append(domain)

    emails = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        content,
    )

    return {
        "urls": urls,
        "domains": domains,
        "emails": list(dict.fromkeys(emails)),
    }
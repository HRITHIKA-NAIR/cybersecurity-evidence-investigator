import re

from app.tools.url_utils import normalize_http_url

MAX_URL_INDICATORS = 20
MAX_EMAIL_INDICATORS = 50
MAX_DOMAIN_INDICATORS = 50


def _bounded_unique(
    values,
    limit: int,
) -> tuple[list[str], bool]:
    unique = list(
        dict.fromkeys(values)
    )
    return (
        unique[:limit],
        len(unique) > limit,
    )


def extract_indicators(content: str):
    urls, urls_truncated = (
        _bounded_unique(
            re.findall(
                r"https?://[^\s<>\"']+",
                content,
            ),
            MAX_URL_INDICATORS,
        )
    )

    emails, emails_truncated = (
        _bounded_unique(
            re.findall(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                content,
            ),
            MAX_EMAIL_INDICATORS,
        )
    )

    domains = []

    for url in urls:
        try:
            _, domain = normalize_http_url(
                url
            )
        except ValueError:
            domain = None

        if (
            domain
            and domain not in domains
        ):
            domains.append(domain)

    for email in emails:
        domain = email.rsplit(
            "@",
            1,
        )[1].lower()

        if domain not in domains:
            domains.append(domain)

    domains_truncated = (
        len(domains)
        > MAX_DOMAIN_INDICATORS
    )
    domains = domains[
        :MAX_DOMAIN_INDICATORS
    ]

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "truncated": {
            "urls": urls_truncated,
            "domains": domains_truncated,
            "emails": emails_truncated,
        },
    }

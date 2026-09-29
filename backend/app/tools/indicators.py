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


_BARE_HOST = re.compile(
    r"^(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#]\S*)?$",
    re.I,
)
_WWW_TOKEN = re.compile(r"(?<![/@\w.])www\.[^\s<>\"']+", re.I)


def _with_schemes(content: str, link_mode: bool) -> str:
    """Give scheme-less addresses an https:// prefix so they are analysed.

    In link mode every token that looks like host/path is treated as a URL
    (people paste "microsoft.com"). Otherwise only www.-prefixed tokens are.
    """
    if link_mode:
        tokens = []
        for token in re.split(r"[\s,;]+", content.strip()):
            trimmed = token.strip("()<>\"'")
            if trimmed and "@" not in trimmed and not trimmed.lower().startswith(("http://", "https://")) and _BARE_HOST.match(trimmed):
                tokens.append("https://" + trimmed)
            else:
                tokens.append(token)
        return " ".join(tokens)
    return _WWW_TOKEN.sub(lambda m: "https://" + m.group(0), content)


def extract_indicators(content: str, *, link_mode: bool = False):
    content = _with_schemes(content, link_mode)
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

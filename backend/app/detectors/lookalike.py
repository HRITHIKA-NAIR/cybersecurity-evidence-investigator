"""Brand look-alike (typosquat / homoglyph) detection for hostnames.

Pure functions, no network. Findings use the same {"type", "message"} shape as
url_detector so they flow into evidence and attack classification. Message
wording deliberately contains "typosquat" / "deceptive characters" because
finding_rules_behavioral keys on those terms.
"""
from __future__ import annotations

import ipaddress
import unicodedata

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# Official registered domains of frequently impersonated brands, including
# services people in the UAE commonly receive scam messages about.
OFFICIAL_DOMAINS: tuple[str, ...] = (
    # global
    "microsoft.com", "office.com", "live.com", "outlook.com", "google.com",
    "gmail.com", "apple.com", "icloud.com", "amazon.com", "amazon.ae",
    "paypal.com", "facebook.com", "instagram.com", "whatsapp.com",
    "netflix.com", "linkedin.com", "dropbox.com", "docusign.com", "dhl.com",
    "fedex.com", "ups.com", "binance.com", "coinbase.com", "twitter.com",
    "telegram.org", "tiktok.com", "youtube.com", "adobe.com", "zoom.us",
    "hsbc.com", "citibank.com", "standardchartered.com", "visa.com",
    "mastercard.com", "stripe.com", "github.com", "outlook.office.com",
    # UAE
    "emirates.com", "etihad.com", "etisalat.ae", "eand.com", "du.ae",
    "dewa.gov.ae", "salik.ae", "rta.ae", "emiratesnbd.com", "adcb.com",
    "mashreqbank.com", "bankfab.com", "dib.ae", "rakbank.ae", "cbd.ae",
    "adib.ae", "noon.com", "talabat.com", "careem.com", "aramex.com",
    "emiratespost.ae", "dubaipolice.gov.ae", "moi.gov.ae", "icp.gov.ae",
    "u.ae", "uaepass.ae", "tdra.gov.ae", "centralbank.ae", "fahr.gov.ae",
    "mohre.gov.ae", "dubai.ae", "smartdubai.ae", "ecrime.ae",
)

_CONFUSABLES = {
    # Cyrillic / Greek / other lookalikes for Latin letters
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ѵ": "v", "һ": "h",
    "ԛ": "q", "ԝ": "w", "ո": "n", "ս": "u", "α": "a", "ο": "o", "ν": "v",
    "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ı": "i", "ⅼ": "l", "ｏ": "o",
    # Latin digits / symbols that mimic letters
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "|": "l", "!": "l", "i": "l",
}

CREDENTIAL_WORDS = (
    "login", "signin", "secure", "verify", "account", "update", "support",
    "wallet", "billing", "confirm", "password", "auth", "recover", "unlock",
)


def _split(hostname: str) -> tuple[str, str, str]:
    """Return (registered_domain, label, subdomain)."""
    extracted = _EXTRACT(hostname)
    if not extracted.domain:
        return "", "", ""
    registered = extracted.domain
    if extracted.suffix:
        registered = f"{extracted.domain}.{extracted.suffix}"
    return registered.lower(), extracted.domain.lower(), extracted.subdomain.lower()


def _decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label
    return label


def fold(text: str) -> str:
    """Collapse look-alike characters so imitations compare equal."""
    text = unicodedata.normalize("NFKC", text).lower().replace("-", "")
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    return text.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def _distance(a: str, b: str) -> int:
    """Optimal string alignment distance (insert/delete/replace/swap)."""
    rows = len(a) + 1
    cols = len(b) + 1
    table = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        table[i][0] = i
    for j in range(cols):
        table[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            table[i][j] = min(
                table[i - 1][j] + 1,
                table[i][j - 1] + 1,
                table[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                table[i][j] = min(table[i][j], table[i - 2][j - 2] + 1)
    return table[-1][-1]


def _scripts(text: str) -> set[str]:
    found = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if name:
                found.add(name.split()[0])
    return found


def _brand_index() -> list[tuple[str, str]]:
    index = []
    for domain in OFFICIAL_DOMAINS:
        _, label, _ = _split(domain)
        if label:
            index.append((label, domain))
    return index


_BRANDS = _brand_index()
_OFFICIAL = set(OFFICIAL_DOMAINS)


def is_official(registered_domain: str) -> bool:
    return registered_domain in _OFFICIAL


def brand_for_label(text: str) -> str | None:
    """Official domain of a brand whose label equals text (exact)."""
    for label, domain in _BRANDS:
        if label == text:
            return domain
    return None


def _finding(kind: str, message: str) -> dict:
    return {"type": kind, "message": message}


def check_hostname(hostname: str) -> list[dict]:
    """Return look-alike findings for one hostname (empty when clean)."""
    hostname = (hostname or "").strip(".").lower()
    if not hostname:
        return []
    try:
        ipaddress.ip_address(hostname)
        return []
    except ValueError:
        pass

    registered, label, subdomain = _split(hostname)
    if not registered or is_official(registered):
        return []

    findings: list[dict] = []
    shown = _decode_label(label)

    scripts = _scripts(shown)
    if len(scripts) > 1:
        findings.append(_finding(
            "suspicious",
            f"Domain {registered} mixes alphabets ({', '.join(sorted(scripts))}) "
            "- deceptive characters commonly used to imitate a real brand",
        ))

    folded = fold(shown)
    reported: set[str] = set()

    for brand_label, official in _BRANDS:
        if brand_label in reported:
            continue
        brand_folded = fold(brand_label)
        if len(brand_label) >= 4 and folded == brand_folded and shown != brand_label:
            findings.append(_finding(
                "suspicious",
                f"'{shown}' imitates {official} using look-alike characters "
                f"(for example 'rn' for 'm' or '0' for 'o') - possible typosquat, "
                f"not the official {official}",
            ))
            reported.add(brand_label)
            continue
        if len(brand_label) >= 6 and shown != brand_label:
            gap = min(_distance(shown, brand_label), _distance(folded, brand_folded))
            limit = 1 if len(brand_label) < 10 else 2
            if gap <= limit:
                findings.append(_finding(
                    "suspicious" if gap <= 1 else "warning",
                    f"'{shown}' is {gap} character(s) away from {official} - "
                    f"possible typosquat, not the official {official}",
                ))
                reported.add(brand_label)
                continue
        tokens = shown.split("-")
        if brand_label in shown and shown != brand_label:
            has_word = any(word in shown for word in CREDENTIAL_WORDS)
            token_hit = len(brand_label) >= 4 and brand_label in tokens
            if len(brand_label) >= 6 or token_hit or (len(brand_label) >= 4 and has_word):
                findings.append(_finding(
                    "suspicious" if has_word else "warning",
                    f"Domain {registered} contains the brand name '{brand_label}' "
                    f"but is not {official} - possible impersonation",
                ))
                reported.add(brand_label)

    for sub_label in [s for s in subdomain.split(".") if s]:
        official = brand_for_label(sub_label)
        if official and sub_label not in reported:
            findings.append(_finding(
                "suspicious",
                f"Subdomain uses the brand name '{sub_label}' but the registered "
                f"domain is {registered}, not {official} - possible impersonation",
            ))
            reported.add(brand_label)

    return findings


def check_email_address(address: str) -> list[dict]:
    if "@" not in address:
        return []
    return check_hostname(address.rsplit("@", 1)[1])

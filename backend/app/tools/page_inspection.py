"""Static inspection of a fetched web page: forms, hidden links, look-alike
link targets, redirects and script tricks. Never executes page JavaScript."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.detectors.lookalike import (
    OFFICIAL_DOMAINS,
    _split,
    check_hostname,
    is_official,
)
from app.security.ssrf import fetch_page

MAX_INSPECTED_LINKS = 400
MAX_EXTERNAL_DOMAINS = 40

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])|"
    r"font-size\s*:\s*0|(?<![-\w])width\s*:\s*0|(?<![-\w])height\s*:\s*0|"
    r"(?:left|top|text-indent)\s*:\s*-\d{3,}",
    re.I,
)
_SENSITIVE_FIELD = re.compile(
    r"otp|pin|cvv|cvc|card|iban|passcode|emirates|eid|ssn|passport|secret", re.I
)
_OBFUSCATION = re.compile(
    r"eval\s*\(|atob\s*\(|unescape\s*\(|String\.fromCharCode|document\.write\s*\(\s*unescape",
    re.I,
)
_JS_REDIRECT = re.compile(
    r"(?:window\.|document\.|top\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()\s*[\"']https?://",
    re.I,
)
_DOWNLOAD_EXT = (
    ".exe", ".msi", ".scr", ".apk", ".bat", ".cmd", ".ps1", ".vbs", ".jar",
    ".iso", ".dmg", ".lnk", ".zip", ".rar", ".7z",
)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
_BRAND_NAMES = {
    "microsoft": "microsoft.com", "google": "google.com", "apple": "apple.com",
    "amazon": "amazon.com", "paypal": "paypal.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "whatsapp": "whatsapp.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "emirates nbd": "emiratesnbd.com", "emirates": "emirates.com",
    "etisalat": "etisalat.ae", "dewa": "dewa.gov.ae", "salik": "salik.ae",
    "adcb": "adcb.com", "mashreq": "mashreqbank.com", "uae pass": "uaepass.ae",
    "dubai police": "dubaipolice.gov.ae", "aramex": "aramex.com",
    "rakbank": "rakbank.ae", "binance": "binance.com",
}


def _finding(kind: str, message: str) -> dict:
    return {"type": kind, "message": message}


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registered(host: str) -> str:
    return _split(host)[0] if host and not _is_ip(host) else host


def _decode(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w-]+)", content_type or "")
    encodings = [match.group(1)] if match else []
    encodings += ["utf-8", "latin-1"]
    for encoding in encodings:
        try:
            return body.decode(encoding, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


def _hidden(tag) -> bool:
    for element in [tag, *tag.parents]:
        attrs = getattr(element, "attrs", None)
        if not attrs:
            continue
        if "hidden" in attrs:
            return True
        if _HIDDEN_STYLE.search(attrs.get("style") or ""):
            return True
    return False


def analyze_html(html: str, final_url: str) -> dict:
    """Inspect HTML text. Pure function (no network) so it is unit-testable."""
    soup = BeautifulSoup(html, "lxml")
    page_host = _host(final_url)
    page_domain = _registered(page_host)
    findings: list[dict] = []
    red_flags = 0

    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""

    # --- forms -----------------------------------------------------------
    forms = []
    for form in soup.find_all("form")[:20]:
        inputs = form.find_all("input")
        types = {(i.get("type") or "text").lower() for i in inputs}
        names = " ".join((i.get("name") or "") + " " + (i.get("id") or "") for i in inputs)
        has_password = "password" in types
        sensitive = bool(_SENSITIVE_FIELD.search(names))
        action = urljoin(final_url, form.get("action") or final_url)
        action_host = _host(action)
        action_domain = _registered(action_host)
        cross = bool(action_domain and page_domain and action_domain != page_domain)
        forms.append({
            "action_host": action_host,
            "has_password_field": has_password,
            "asks_sensitive_data": sensitive,
            "sends_to_other_domain": cross,
            "method": (form.get("method") or "get").lower(),
        })
        if (has_password or sensitive) and cross:
            red_flags += 1
            findings.append(_finding(
                "suspicious",
                f"Login/payment form sends entered data to a different domain "
                f"({action_domain}) than the page ({page_domain}) - credential "
                "form on another domain",
            ))
        elif has_password and action.startswith("http://"):
            red_flags += 1
            findings.append(_finding("suspicious", "Password form submits over unencrypted HTTP"))
        elif has_password and forms[-1]["method"] == "get":
            findings.append(_finding("warning", "Password form uses GET, which puts the password in the URL"))

    # --- meta refresh / script redirects ---------------------------------
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        content = meta.get("content") or ""
        match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.I)
        if match:
            target = urljoin(final_url, match.group(1).strip())
            target_domain = _registered(_host(target))
            if target_domain and target_domain != page_domain:
                red_flags += 1
                findings.append(_finding("warning", f"Page automatically redirects (meta refresh) to another domain: {target_domain}"))

    script_domains: set[str] = set()
    obfuscated = js_redirect = False
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            domain = _registered(_host(urljoin(final_url, src)))
            if domain and domain != page_domain:
                script_domains.add(domain)
        text = script.string or script.get_text() or ""
        if text:
            obfuscated = obfuscated or bool(_OBFUSCATION.search(text))
            js_redirect = js_redirect or bool(_JS_REDIRECT.search(text))
    if obfuscated:
        red_flags += 1
        findings.append(_finding("warning", "Page contains obfuscated script (eval/atob/unescape), often used to hide malicious behaviour"))
    if js_redirect:
        findings.append(_finding("warning", "Page script redirects the browser to an absolute web address"))

    # --- iframes ---------------------------------------------------------
    iframes = []
    for frame in soup.find_all("iframe")[:20]:
        src = urljoin(final_url, frame.get("src") or "")
        domain = _registered(_host(src))
        tiny = any((frame.get(k) or "").strip() in {"0", "1"} for k in ("width", "height"))
        hidden = tiny or _hidden(frame)
        iframes.append({"domain": domain, "hidden": hidden})
        if hidden and domain and domain != page_domain:
            red_flags += 1
            findings.append(_finding("suspicious", f"Hidden frame loads content from another domain ({domain})"))

    # --- links -----------------------------------------------------------
    external: dict[str, int] = {}
    hidden_links: list[dict] = []
    mismatched: list[dict] = []
    downloads: list[str] = []
    shorteners: set[str] = set()
    links = soup.find_all("a", href=True)[:MAX_INSPECTED_LINKS]

    for anchor in links:
        href = anchor["href"].strip()
        if href.startswith(("#", "mailto:", "tel:", "javascript:", "sms:")):
            continue
        absolute = urljoin(final_url, href)
        host = _host(absolute)
        if not host:
            continue
        domain = _registered(host)
        is_external = bool(domain and domain != page_domain)
        text = anchor.get_text(" ", strip=True)

        if is_external:
            external[domain] = external.get(domain, 0) + 1
            if domain in _SHORTENERS:
                shorteners.add(domain)
            if _hidden(anchor):
                hidden_links.append({"domain": domain, "text": text[:60]})
            shown = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower())
            if shown:
                shown_domain = _registered(shown.group(1))
                if shown_domain and shown_domain != domain:
                    mismatched.append({"shown": shown_domain, "goes_to": domain})
        path = urlsplit(absolute).path.lower()
        if path.endswith(_DOWNLOAD_EXT) or anchor.has_attr("download"):
            downloads.append(f"{path.rsplit('/', 1)[-1] or 'file'} from {domain or host}")

    # hidden cross-domain links
    if hidden_links:
        domains = sorted({item["domain"] for item in hidden_links})
        red_flags += 1
        findings.append(_finding(
            "suspicious",
            f"{len(hidden_links)} hidden link(s) point to other domains ({', '.join(domains[:5])}) - "
            "invisible links are a common way to hide redirects and tracking",
        ))
    if mismatched:
        red_flags += 1
        sample = mismatched[0]
        findings.append(_finding(
            "suspicious",
            f"{len(mismatched)} link(s) show one web address but go to another "
            f"(e.g. shows {sample['shown']}, goes to {sample['goes_to']}) - deceptive link text",
        ))
    if downloads:
        red_flags += 1
        findings.append(_finding("warning", f"Page links to downloadable program/archive files ({'; '.join(downloads[:3])})"))
    if shorteners:
        findings.append(_finding("warning", f"Page links through URL shorteners ({', '.join(sorted(shorteners))}), which hide the real destination"))
    ip_links = [d for d in external if _is_ip(d)]
    if ip_links:
        red_flags += 1
        findings.append(_finding("suspicious", f"Page links to raw IP addresses ({', '.join(ip_links[:3])}) instead of named sites"))

    # look-alike check of every external domain the page points to
    for domain in list(external)[:MAX_EXTERNAL_DOMAINS]:
        if _is_ip(domain):
            continue
        for item in check_hostname(domain):
            if item["type"] == "suspicious":
                red_flags += 1
                findings.append(_finding(
                    "suspicious",
                    f"Page links to {domain}: {item['message']}",
                ))
                break

    # --- brand claim vs hosting domain ------------------------------------
    heading = soup.find(["h1", "h2"])
    claim_text = " ".join(filter(None, [
        title,
        heading.get_text(" ", strip=True) if heading else "",
        (soup.find("meta", attrs={"property": "og:site_name"}) or {}).get("content", ""),
    ])).lower()
    asks_login = any(f["has_password_field"] or f["asks_sensitive_data"] for f in forms)
    if asks_login and page_domain and not is_official(page_domain):
        for name, official in _BRAND_NAMES.items():
            if re.search(rf"\b{re.escape(name)}\b", claim_text):
                red_flags += 1
                findings.append(_finding(
                    "suspicious",
                    f"Page presents itself as {name.title()} and asks for login or payment data, "
                    f"but is hosted on {page_domain}, not {official} - possible impersonation",
                ))
                break

    if not red_flags:
        findings.append(_finding(
            "positive",
            "Fetched page has no cross-domain login form, hidden cross-domain links, "
            "look-alike link targets or obfuscated script (static check only)",
        ))

    return {
        "status": "inspected",
        "final_url": final_url,
        "title": title[:200],
        "form_count": len(forms),
        "forms": forms[:10],
        "link_count": len(links),
        "external_domains": sorted(external, key=lambda d: -external[d])[:20],
        "hidden_links": hidden_links[:10],
        "mismatched_links": mismatched[:10],
        "iframes": iframes[:10],
        "script_domains": sorted(script_domains)[:20],
        "red_flag_count": red_flags,
        "findings": findings,
        "limits": [
            "Static HTML only: page JavaScript was not executed.",
            "Content behind logins, CAPTCHAs or geo-blocks was not seen.",
            "A clean page today does not guarantee it stays clean.",
        ],
    }


def inspect_page(url: str) -> dict:
    """Fetch (SSRF-safe, bounded) and inspect one URL."""
    fetched = fetch_page(url)
    if fetched.get("status") != "fetched":
        return {
            "status": fetched.get("status", "error"),
            "reason": fetched.get("reason", "Page could not be inspected."),
            "findings": [],
            "limits": ["The page could not be fetched, so its content was not inspected."],
        }
    html = _decode(fetched["body"], fetched.get("content_type", ""))
    result = analyze_html(html, fetched["final_url"])
    result["truncated"] = fetched.get("truncated", False)
    result["status_code"] = fetched.get("status_code")
    return result

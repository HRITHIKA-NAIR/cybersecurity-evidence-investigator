from __future__ import annotations

import re
import zipfile
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
DECOY_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".txt",
}
EXEC_EXTS = {".exe", ".dll", ".msi", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".lnk"}
IGNORED_URLS = {"http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink"}
MIME = {
    ".txt": {"text/plain"},
    ".md": {"text/markdown", "text/plain"},
    ".csv": {"text/csv", "application/vnd.ms-excel", "text/plain"},
    ".json": {"application/json", "text/json", "text/plain"},
    ".eml": {"message/rfc822"},
    ".pdf": {"application/pdf"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".html": {"text/html", "text/plain"},
    ".htm": {"text/html", "text/plain"},
    ".svg": {"image/svg+xml", "text/xml", "application/xml", "text/plain"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".gif": {"image/gif"},
    ".bmp": {"image/bmp"},
    ".webp": {"image/webp"},
}
SEVERITY = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}


def _finding(name, category, severity, evidence, status="Detected", confidence=100):
    return {
        "attack_type": name,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "evidence": evidence,
    }


def _unique(values):
    return list(dict.fromkeys(value for value in values if value))


def _filename_findings(filename):
    findings = []
    suffixes = [suffix.lower() for suffix in Path(filename).suffixes]

    if len(suffixes) >= 2:
        final_extension = suffixes[-1]
        decoy_extensions = [
            suffix
            for suffix in suffixes[:-1]
            if suffix in DECOY_EXTS
            and suffix != final_extension
        ]

        if decoy_extensions:
            findings.append(_finding(
                "Double Extension", "Filename Deception", "Medium",
                [
                    "Filename contains a decoy extension before "
                    f"the final extension: {filename}"
                ],
                "Indicator Present", 95,
            ))

    if any(char in filename for char in BIDI):
        findings.append(_finding(
            "Bidirectional Unicode Control", "Filename Deception", "High",
            ["Filename contains a bidirectional Unicode control character that can alter displayed order."],
        ))

    return findings


def _mime_findings(extension, declared_mime):
    if not declared_mime:
        return []

    declared = declared_mime.split(";", 1)[0].strip().lower()
    expected = MIME.get(extension)
    if not expected or declared in expected or declared in {"", "application/octet-stream"}:
        return []

    return [_finding(
        "Declared MIME Mismatch", "File Metadata", "Low",
        [f"Extension {extension} was uploaded as {declared}."],
        "Indicator Present", 90,
    )]


def _office_analysis(data):
    findings, urls = [], []

    with zipfile.ZipFile(BytesIO(data)) as archive:
        names = archive.namelist()
        lower_names = [name.lower() for name in names]

        groups = (
            ("VBA Macro Project Present", "Office Active Content", "Medium",
             [name for name in names if name.lower().endswith("vbaproject.bin")]),
            ("Embedded Object Present", "Office Embedded Content", "Medium",
             [name for name in names if "/embeddings/" in name.lower() or "oleobject" in name.lower()]),
            ("ActiveX Content Present", "Office Active Content", "Medium",
             [name for name in names if "/activex/" in name.lower()]),
        )
        for name, category, severity, matches in groups:
            if matches:
                findings.append(_finding(
                    name, category, severity,
                    [f"OOXML package contains: {', '.join(matches[:5])}"],
                ))

        external, templates = [], []
        for index, name in enumerate(names):
            lower = lower_names[index]

            if lower.endswith(".rels"):
                try:
                    root = ElementTree.fromstring(archive.read(name))
                except (ElementTree.ParseError, KeyError):
                    continue

                for relation in root.iter():
                    if relation.attrib.get("TargetMode", "").lower() != "external":
                        continue
                    target = relation.attrib.get("Target", "")
                    rel_type = relation.attrib.get("Type", "")
                    if target:
                        external.append(target)
                        if target.lower().startswith(("http://", "https://")):
                            urls.append(target)
                    if "attachedtemplate" in rel_type.lower() and target:
                        templates.append(target)

            elif lower.endswith((".xml", ".txt")):
                try:
                    text = archive.read(name).decode("utf-8", errors="ignore")
                except KeyError:
                    continue
                if re.search(r"\bDDE(?:AUTO)?\b", text, re.I):
                    findings.append(_finding(
                        "DDE Field Indicator", "Office Active Content", "High",
                        [f"Office XML part {name} contains a DDE/DDEAUTO field indicator."],
                        "Indicator Present", 90,
                    ))
                    break

        if external:
            findings.append(_finding(
                "External Office Relationship", "Office External Content", "Medium",
                [f"External target: {target}" for target in external[:5]],
            ))
        if templates:
            findings.append(_finding(
                "External Template Relationship", "Office External Content", "High",
                [f"External template: {target}" for target in templates[:5]],
            ))

    return findings, _unique(urls)


def _pdf_analysis(data):
    text = data.decode("latin-1", errors="ignore")
    findings = []
    tokens = {
        "/JavaScript": ("PDF JavaScript", "PDF Active Content", "High"),
        "/OpenAction": ("PDF Open Action", "PDF Active Content", "Medium"),
        "/Launch": ("PDF Launch Action", "PDF Active Content", "High"),
        "/EmbeddedFile": ("Embedded PDF File", "PDF Embedded Content", "Medium"),
        "/AcroForm": ("Interactive PDF Form", "PDF Form Content", "Low"),
        "/RichMedia": ("PDF Rich Media", "PDF Active Content", "Medium"),
    }

    for token, (name, category, severity) in tokens.items():
        if token in text:
            findings.append(_finding(name, category, severity, [f"PDF structure contains {token}."]))

    if re.search(r"/AA\b", text):
        findings.append(_finding(
            "PDF Additional Action", "PDF Active Content", "Medium",
            ["PDF structure contains /AA additional actions."],
        ))

    return findings, _unique(URL_RE.findall(text))


class _MarkupInspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.counts = {"script": 0, "iframe": 0, "form": 0, "password": 0, "refresh": 0, "events": 0, "download": 0}
        self.urls = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = {name.lower(): value or "" for name, value in attrs}
        if tag in {"script", "iframe", "form"}:
            self.counts[tag] += 1
        if tag == "input" and attrs.get("type", "").lower() == "password":
            self.counts["password"] += 1
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            self.counts["refresh"] += 1
        self.counts["events"] += sum(name.startswith("on") for name in attrs)
        self.counts["download"] += int("download" in attrs)

        for name in ("href", "src", "action", "data"):
            value = attrs.get(name, "")
            if value.lower().startswith(("http://", "https://")):
                self.urls.append(value)


def _markup_analysis(data, extension):
    text = data.decode("utf-8", errors="replace")
    parser = _MarkupInspector()
    try:
        parser.feed(text)
    except Exception:
        pass

    kind = "SVG" if extension == ".svg" else "HTML"
    findings = []
    checks = (
        ("script", f"{kind} Script Content", "Web Active Content", "Medium", "script element(s)"),
        ("iframe", f"{kind} Iframe Content", "Web Embedded Content", "Medium", "iframe element(s)"),
        ("password", "Password Input Form", "Credential Collection", "High", "password input field(s)"),
        ("refresh", "Meta Refresh Redirect", "Web Redirect", "Medium", "meta refresh directive(s)"),
        ("events", "Inline Event Handler", "Web Active Content", "Low", "inline event handler(s)"),
        ("download", "Download Attribute Present", "Web Download", "Low", "download-enabled link(s)"),
    )
    for key, name, category, severity, label in checks:
        count = parser.counts[key]
        if count:
            findings.append(_finding(name, category, severity, [f"{kind} contains {count} {label}."]))

    lower = text.lower()
    if any(token in lower for token in ("window.location", "location.href", "document.location")):
        findings.append(_finding(
            "Scripted Navigation", "Web Redirect", "High",
            [f"{kind} contains scripted navigation logic."],
            "Indicator Present", 95,
        ))
    if any(token in lower for token in ("data:text/html;base64,", "data:application/", "atob(", "eval(")):
        findings.append(_finding(
            "Encoded or Obfuscated Web Content", "Web Obfuscation", "Medium",
            [f"{kind} contains an encoding or execution primitive commonly used to hide content."],
            "Indicator Present", 90,
        ))

    urls = [url for url in parser.urls + URL_RE.findall(text) if url not in IGNORED_URLS]
    return findings, _unique(urls)


def _archive_analysis(data):
    with zipfile.ZipFile(BytesIO(data)) as archive:
        infos = archive.infolist()

    findings = []

    for info in infos:
        findings.extend(
            _filename_findings(
                Path(info.filename).name
            )
        )

    executable = [info.filename for info in infos if Path(info.filename).suffix.lower() in EXEC_EXTS]
    traversal = [
        info.filename for info in infos
        if info.filename.startswith(("/", "\\")) or ".." in Path(info.filename).parts
    ]
    encrypted = [info.filename for info in infos if info.flag_bits & 0x1]

    if executable:
        findings.append(_finding(
            "Executable or Script in Archive", "Archive Content", "High",
            [f"Archive contains potentially executable or script content: {', '.join(executable[:5])}"],
        ))
    if traversal:
        findings.append(_finding(
            "Archive Path Traversal Name", "Archive Structure", "High",
            [f"Archive contains path traversal style name(s): {', '.join(traversal[:5])}"],
        ))
    if encrypted:
        findings.append(_finding(
            "Encrypted Archive Entry", "Archive Visibility", "Medium",
            ["Archive contains encrypted entries that cannot be statically inspected."],
        ))

    return findings, []


def analyze_file(filename, extension, declared_mime, detected_type, data):
    findings = _filename_findings(filename) + _mime_findings(extension, declared_mime)
    urls = []

    try:
        if extension in {".docx", ".pptx", ".xlsx"}:
            extra_findings, urls = _office_analysis(data)
        elif extension == ".pdf":
            extra_findings, urls = _pdf_analysis(data)
        elif extension in {".html", ".htm", ".svg"}:
            extra_findings, urls = _markup_analysis(data, extension)
        elif extension == ".zip":
            extra_findings, urls = _archive_analysis(data)
        else:
            extra_findings = []
    except (OSError, ValueError, zipfile.BadZipFile):
        extra_findings = []

    findings.extend(extra_findings)
    highest = max(
        (finding["severity"] for finding in findings),
        key=lambda value: SEVERITY[value],
        default="Info",
    )

    return {
        "detected_type": detected_type,
        "findings": findings,
        "urls": _unique(urls),
        "finding_count": len(findings),
        "highest_severity": highest,
        "analysis_mode": "static_only",
        "executed": False,
    }

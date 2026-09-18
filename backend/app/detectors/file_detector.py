from __future__ import annotations

import re
import zipfile
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

URL_RE = re.compile(
    r"https?://[^\s\"'<>\\)]+",
    re.IGNORECASE,
)
BIDI_CONTROLS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}
DECOY_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".txt",
}
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".msi",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    ".lnk",
}
EXPECTED_MIME = {
    ".txt": {"text/plain"},
    ".md": {"text/markdown", "text/plain"},
    ".csv": {"text/csv", "application/vnd.ms-excel", "text/plain"},
    ".json": {"application/json", "text/json", "text/plain"},
    ".eml": {"message/rfc822", "application/octet-stream"},
    ".pdf": {"application/pdf"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    },
    ".pptx": {
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    },
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    },
    ".html": {"text/html", "text/plain"},
    ".htm": {"text/html", "text/plain"},
    ".svg": {"image/svg+xml", "text/xml", "application/xml", "text/plain"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
}
IGNORED_MARKUP_URLS = {
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xlink",
}
SEVERITY_ORDER = {
    "Info": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
}


def _finding(
    attack_type: str,
    category: str,
    severity: str,
    evidence: list[str],
    *,
    status: str = "Detected",
    confidence: int = 100,
) -> dict:
    return {
        "attack_type": attack_type,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "evidence": evidence,
    }


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _filename_findings(filename: str) -> list[dict]:
    findings = []
    suffixes = [
        suffix.lower()
        for suffix in Path(filename).suffixes
    ]

    if (
        len(suffixes) >= 2
        and suffixes[-2] in DECOY_EXTENSIONS
        and suffixes[-1] != suffixes[-2]
    ):
        findings.append(
            _finding(
                "Double Extension",
                "Filename Deception",
                "Medium",
                [
                    "Filename uses consecutive extensions: "
                    + "".join(suffixes[-2:])
                ],
                status="Indicator Present",
                confidence=95,
            )
        )

    if any(char in filename for char in BIDI_CONTROLS):
        findings.append(
            _finding(
                "Bidirectional Unicode Control",
                "Filename Deception",
                "High",
                [
                    "Filename contains a bidirectional Unicode "
                    "control character that can alter displayed order."
                ],
                status="Detected",
            )
        )

    return findings


def _mime_findings(
    extension: str,
    declared_mime: str | None,
) -> list[dict]:
    if not declared_mime:
        return []

    normalized = declared_mime.split(";", 1)[0].strip().lower()

    if normalized in {"", "application/octet-stream"}:
        return []

    expected = EXPECTED_MIME.get(extension)

    if expected and normalized not in expected:
        return [
            _finding(
                "Declared MIME Mismatch",
                "File Metadata",
                "Low",
                [
                    f"Extension {extension} was uploaded as "
                    f"{normalized}."
                ],
                status="Indicator Present",
                confidence=90,
            )
        ]

    return []


def _office_analysis(data: bytes) -> tuple[list[dict], list[str]]:
    findings = []
    urls = []

    with zipfile.ZipFile(BytesIO(data)) as archive:
        names = archive.namelist()

        macro_parts = [
            name
            for name in names
            if name.lower().endswith("vbaproject.bin")
        ]
        if macro_parts:
            findings.append(
                _finding(
                    "VBA Macro Project Present",
                    "Office Active Content",
                    "Medium",
                    [
                        "OOXML package contains "
                        + ", ".join(macro_parts[:5])
                    ],
                    status="Detected",
                )
            )

        embedded = [
            name
            for name in names
            if "/embeddings/" in name.lower()
            or "oleobject" in name.lower()
        ]
        if embedded:
            findings.append(
                _finding(
                    "Embedded Object Present",
                    "Office Embedded Content",
                    "Medium",
                    [
                        "OOXML package contains embedded object part(s): "
                        + ", ".join(embedded[:5])
                    ],
                    status="Detected",
                )
            )

        activex = [
            name
            for name in names
            if "/activex/" in name.lower()
        ]
        if activex:
            findings.append(
                _finding(
                    "ActiveX Content Present",
                    "Office Active Content",
                    "Medium",
                    [
                        "OOXML package contains ActiveX part(s): "
                        + ", ".join(activex[:5])
                    ],
                    status="Detected",
                )
            )

        external_targets = []
        external_templates = []

        for name in names:
            lower = name.lower()

            if lower.endswith(".rels"):
                try:
                    root = ElementTree.fromstring(
                        archive.read(name)
                    )
                except (ElementTree.ParseError, KeyError):
                    continue

                for relationship in root.iter():
                    target = relationship.attrib.get("Target", "")
                    mode = relationship.attrib.get(
                        "TargetMode",
                        "",
                    )
                    relation_type = relationship.attrib.get(
                        "Type",
                        "",
                    )

                    if mode.lower() != "external":
                        continue

                    if target:
                        external_targets.append(target)

                        if target.lower().startswith(
                            ("http://", "https://")
                        ):
                            urls.append(target)

                    if (
                        "attachedtemplate"
                        in relation_type.lower()
                    ):
                        external_templates.append(target)

            elif lower.endswith((".xml", ".txt")):
                try:
                    text = archive.read(name).decode(
                        "utf-8",
                        errors="ignore",
                    )
                except KeyError:
                    continue

                if re.search(
                    r"\bDDE(?:AUTO)?\b",
                    text,
                    re.IGNORECASE,
                ):
                    findings.append(
                        _finding(
                            "DDE Field Indicator",
                            "Office Active Content",
                            "High",
                            [
                                f"Office XML part {name} contains "
                                "a DDE/DDEAUTO field indicator."
                            ],
                            status="Indicator Present",
                            confidence=90,
                        )
                    )
                    break

        if external_targets:
            findings.append(
                _finding(
                    "External Office Relationship",
                    "Office External Content",
                    "Medium",
                    [
                        "OOXML relationship points to external target: "
                        + target
                        for target in external_targets[:5]
                    ],
                    status="Detected",
                )
            )

        if external_templates:
            findings.append(
                _finding(
                    "External Template Relationship",
                    "Office External Content",
                    "High",
                    [
                        "OOXML document references external template: "
                        + target
                        for target in external_templates[:5]
                    ],
                    status="Detected",
                )
            )

    return findings, _unique(urls)


def _pdf_analysis(data: bytes) -> tuple[list[dict], list[str]]:
    text = data.decode(
        "latin-1",
        errors="ignore",
    )
    findings = []

    tokens = (
        (
            "/JavaScript",
            "PDF JavaScript",
            "PDF Active Content",
            "High",
        ),
        (
            "/OpenAction",
            "PDF Open Action",
            "PDF Active Content",
            "Medium",
        ),
        (
            "/Launch",
            "PDF Launch Action",
            "PDF Active Content",
            "High",
        ),
        (
            "/EmbeddedFile",
            "Embedded PDF File",
            "PDF Embedded Content",
            "Medium",
        ),
        (
            "/AcroForm",
            "Interactive PDF Form",
            "PDF Form Content",
            "Low",
        ),
        (
            "/RichMedia",
            "PDF Rich Media",
            "PDF Active Content",
            "Medium",
        ),
    )

    for token, attack_type, category, severity in tokens:
        if token in text:
            findings.append(
                _finding(
                    attack_type,
                    category,
                    severity,
                    [f"PDF structure contains {token}."],
                    status="Detected",
                )
            )

    if re.search(r"/AA\b", text):
        findings.append(
            _finding(
                "PDF Additional Action",
                "PDF Active Content",
                "Medium",
                ["PDF structure contains /AA additional actions."],
                status="Detected",
            )
        )

    return findings, _unique(URL_RE.findall(text))


class _MarkupInspector(HTMLParser):
    def __init__(self):
        super().__init__(
            convert_charrefs=True
        )
        self.script_count = 0
        self.iframe_count = 0
        self.password_inputs = 0
        self.forms = 0
        self.meta_refresh = 0
        self.event_handlers = 0
        self.download_links = 0
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attributes = {
            name.lower(): value or ""
            for name, value in attrs
        }

        if tag == "script":
            self.script_count += 1

        if tag == "iframe":
            self.iframe_count += 1

        if tag == "form":
            self.forms += 1

        if (
            tag == "input"
            and attributes.get(
                "type",
                "",
            ).lower()
            == "password"
        ):
            self.password_inputs += 1

        if (
            tag == "meta"
            and attributes.get(
                "http-equiv",
                "",
            ).lower()
            == "refresh"
        ):
            self.meta_refresh += 1

        self.event_handlers += sum(
            1
            for name in attributes
            if name.startswith("on")
        )

        if "download" in attributes:
            self.download_links += 1

        for name in (
            "href",
            "src",
            "action",
            "data",
        ):
            value = attributes.get(name, "")

            if value.lower().startswith(
                ("http://", "https://")
            ):
                self.urls.append(value)


def _markup_analysis(
    data: bytes,
    extension: str,
) -> tuple[list[dict], list[str]]:
    text = data.decode(
        "utf-8",
        errors="replace",
    )
    inspector = _MarkupInspector()

    try:
        inspector.feed(text)
    except Exception:
        pass

    findings = []
    kind = "SVG" if extension == ".svg" else "HTML"

    if inspector.script_count:
        findings.append(
            _finding(
                f"{kind} Script Content",
                "Web Active Content",
                "Medium",
                [
                    f"{kind} contains {inspector.script_count} "
                    "script element(s)."
                ],
                status="Detected",
            )
        )

    if inspector.iframe_count:
        findings.append(
            _finding(
                f"{kind} Iframe Content",
                "Web Embedded Content",
                "Medium",
                [
                    f"{kind} contains {inspector.iframe_count} "
                    "iframe element(s)."
                ],
                status="Detected",
            )
        )

    if inspector.password_inputs:
        findings.append(
            _finding(
                "Password Input Form",
                "Credential Collection",
                "High",
                [
                    f"{kind} contains {inspector.password_inputs} "
                    "password input field(s)."
                ],
                status="Detected",
            )
        )

    if inspector.meta_refresh:
        findings.append(
            _finding(
                "Meta Refresh Redirect",
                "Web Redirect",
                "Medium",
                [
                    f"{kind} contains a meta refresh directive."
                ],
                status="Detected",
            )
        )

    if inspector.event_handlers:
        findings.append(
            _finding(
                "Inline Event Handler",
                "Web Active Content",
                "Low",
                [
                    f"{kind} contains {inspector.event_handlers} "
                    "inline event handler attribute(s)."
                ],
                status="Detected",
            )
        )

    if inspector.download_links:
        findings.append(
            _finding(
                "Download Attribute Present",
                "Web Download",
                "Low",
                [
                    f"{kind} contains {inspector.download_links} "
                    "download-enabled link(s)."
                ],
                status="Detected",
            )
        )

    lower = text.lower()

    if (
        "window.location" in lower
        or "location.href" in lower
        or "document.location" in lower
    ):
        findings.append(
            _finding(
                "Scripted Navigation",
                "Web Redirect",
                "High",
                [
                    f"{kind} contains scripted navigation logic."
                ],
                status="Indicator Present",
                confidence=95,
            )
        )

    if (
        "data:text/html;base64," in lower
        or "data:application/" in lower
        or "atob(" in lower
        or "eval(" in lower
    ):
        findings.append(
            _finding(
                "Encoded or Obfuscated Web Content",
                "Web Obfuscation",
                "Medium",
                [
                    f"{kind} contains an encoding or execution "
                    "primitive commonly used to hide content."
                ],
                status="Indicator Present",
                confidence=90,
            )
        )

    urls = [
        url
        for url in (
            inspector.urls
            + URL_RE.findall(text)
        )
        if url not in IGNORED_MARKUP_URLS
    ]
    return findings, _unique(urls)


def _archive_analysis(data: bytes) -> tuple[list[dict], list[str]]:
    findings = []

    with zipfile.ZipFile(BytesIO(data)) as archive:
        infos = archive.infolist()

    executable_names = [
        info.filename
        for info in infos
        if Path(info.filename).suffix.lower()
        in EXECUTABLE_EXTENSIONS
    ]

    if executable_names:
        findings.append(
            _finding(
                "Executable or Script in Archive",
                "Archive Content",
                "High",
                [
                    "Archive contains potentially executable "
                    "or script content: "
                    + ", ".join(executable_names[:5])
                ],
                status="Detected",
            )
        )

    traversal_names = [
        info.filename
        for info in infos
        if (
            info.filename.startswith(("/", "\\"))
            or ".." in Path(info.filename).parts
        )
    ]

    if traversal_names:
        findings.append(
            _finding(
                "Archive Path Traversal Name",
                "Archive Structure",
                "High",
                [
                    "Archive contains path traversal style name(s): "
                    + ", ".join(traversal_names[:5])
                ],
                status="Detected",
            )
        )

    encrypted_names = [
        info.filename
        for info in infos
        if info.flag_bits & 0x1
    ]

    if encrypted_names:
        findings.append(
            _finding(
                "Encrypted Archive Entry",
                "Archive Visibility",
                "Medium",
                [
                    "Archive contains encrypted entry or entries "
                    "that cannot be statically inspected."
                ],
                status="Detected",
            )
        )

    return findings, []


def analyze_file(
    filename: str,
    extension: str,
    declared_mime: str | None,
    detected_type: str,
    data: bytes,
) -> dict:
    findings = []
    urls = []

    findings.extend(
        _filename_findings(filename)
    )
    findings.extend(
        _mime_findings(
            extension,
            declared_mime,
        )
    )

    try:
        if extension in {
            ".docx",
            ".pptx",
            ".xlsx",
        }:
            type_findings, type_urls = (
                _office_analysis(data)
            )
        elif extension == ".pdf":
            type_findings, type_urls = (
                _pdf_analysis(data)
            )
        elif extension in {
            ".html",
            ".htm",
            ".svg",
        }:
            type_findings, type_urls = (
                _markup_analysis(
                    data,
                    extension,
                )
            )
        elif extension == ".zip":
            type_findings, type_urls = (
                _archive_analysis(data)
            )
        else:
            type_findings, type_urls = (
                [],
                [],
            )
    except (
        OSError,
        ValueError,
        zipfile.BadZipFile,
    ):
        type_findings, type_urls = (
            [],
            [],
        )

    findings.extend(type_findings)
    urls.extend(type_urls)

    highest = "Info"

    for finding in findings:
        if (
            SEVERITY_ORDER[
                finding["severity"]
            ]
            > SEVERITY_ORDER[highest]
        ):
            highest = finding[
                "severity"
            ]

    return {
        "detected_type": detected_type,
        "findings": findings,
        "urls": _unique(urls),
        "finding_count": len(findings),
        "highest_severity": highest,
        "analysis_mode": "static_only",
        "executed": False,
    }

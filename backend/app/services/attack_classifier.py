from __future__ import annotations

from app.models import AttackFinding, EvidenceItem

SEVERITY_ORDER = {
    "Info": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}
STATUS_ORDER = {
    "Insufficient Evidence": 0,
    "Not Applicable": 0,
    "Requires Dynamic Analysis": 1,
    "Indicator Present": 2,
    "Likely": 3,
    "Detected": 4,
}
URL_DECEPTION_TERMS = (
    "Punycode",
    "subdomain",
    "user-info",
    "IP address",
    "non-standard port",
    "percent-encoded",
    "double encoding",
    "deceptive characters",
    "typosquat",
)


def _matching(
    evidence_items: list[EvidenceItem],
    evidence_type: str,
) -> list[EvidenceItem]:
    return [
        item
        for item in evidence_items
        if item.type == evidence_type
    ]


def _new_finding(
    attack_type: str,
    category: str,
    severity: str,
    status: str,
    confidence: int,
    evidence_ids: list[str],
    detector: str,
    limitations: list[str] | None = None,
) -> AttackFinding:
    return AttackFinding(
        attack_type=attack_type,
        category=category,
        severity=severity,
        status=status,
        confidence=confidence,
        evidence_ids=list(
            dict.fromkeys(evidence_ids)
        ),
        detector=detector,
        limitations=limitations or [],
    )


def _merge_findings(
    findings: list[AttackFinding],
) -> list[AttackFinding]:
    merged: dict[
        tuple[str, str],
        AttackFinding,
    ] = {}

    for finding in findings:
        key = (
            finding.attack_type,
            finding.category,
        )
        existing = merged.get(key)

        if not existing:
            merged[key] = finding
            continue

        existing.evidence_ids = list(
            dict.fromkeys(
                existing.evidence_ids
                + finding.evidence_ids
            )
        )
        existing.confidence = max(
            existing.confidence,
            finding.confidence,
        )

        if (
            SEVERITY_ORDER[
                finding.severity
            ]
            > SEVERITY_ORDER[
                existing.severity
            ]
        ):
            existing.severity = (
                finding.severity
            )

        if (
            STATUS_ORDER[
                finding.status
            ]
            > STATUS_ORDER[
                existing.status
            ]
        ):
            existing.status = finding.status

        existing.limitations = list(
            dict.fromkeys(
                existing.limitations
                + finding.limitations
            )
        )

    return list(merged.values())


def classify_attack_findings(
    evidence_items: list[EvidenceItem],
) -> list[AttackFinding]:
    findings: list[AttackFinding] = []

    for item in _matching(
        evidence_items,
        "file_finding",
    ):
        value = item.value

        findings.append(
            _new_finding(
                value["attack_type"],
                value["category"],
                value.get(
                    "severity",
                    "Medium",
                ),
                value.get(
                    "status",
                    "Indicator Present",
                ),
                int(
                    value.get(
                        "confidence",
                        80,
                    )
                ),
                [item.id],
                "file_detector",
                [
                    "Static analysis only; "
                    "the artifact was not executed."
                ],
            )
        )

    social_items = _matching(
        evidence_items,
        "social_engineering",
    )

    for item in social_items:
        value = item.value

        findings.append(
            _new_finding(
                value["signal"],
                value.get(
                    "category",
                    "Social Engineering",
                ),
                value.get(
                    "severity",
                    "Medium",
                ),
                value.get(
                    "status",
                    "Indicator Present",
                ),
                int(
                    value.get(
                        "confidence",
                        80,
                    )
                ),
                [item.id],
                "social_engineering",
                [
                    "Language indicators do not "
                    "by themselves establish "
                    "malicious intent."
                ],
            )
        )

    url_items = [
        item
        for item in _matching(
            evidence_items,
            "url_finding",
        )
        if item.value.get(
            "type"
        )
        in {"warning", "suspicious"}
        and any(
            term.lower()
            in item.value.get(
                "message",
                "",
            ).lower()
            for term in URL_DECEPTION_TERMS
        )
    ]

    if url_items:
        severity = (
            "High"
            if any(
                item.value.get(
                    "type"
                )
                == "suspicious"
                for item in url_items
            )
            else "Medium"
        )
        findings.append(
            _new_finding(
                "URL Deception Indicators",
                "URL / Web",
                severity,
                "Indicator Present",
                88,
                [
                    item.id
                    for item in url_items
                ],
                "url_detector",
                [
                    "URL structure heuristics "
                    "are indicators, not proof "
                    "of a malicious destination."
                ],
            )
        )

    redirect_items = _matching(
        evidence_items,
        "redirect_chain",
    )

    if redirect_items:
        findings.append(
            _new_finding(
                "Redirect Chain",
                "URL Behavior",
                "Medium",
                "Detected",
                100,
                [
                    item.id
                    for item in redirect_items
                ],
                "ssrf_redirect",
                [
                    "A redirect chain can be "
                    "benign or malicious; context "
                    "is required."
                ],
            )
        )

    qr_urls = [
        item
        for item in _matching(
            evidence_items,
            "qr_payload",
        )
        if str(
            item.value.get(
                "payload",
                "",
            )
        ).lower().startswith(
            ("http://", "https://")
        )
    ]

    if qr_urls:
        findings.append(
            _new_finding(
                "QR Link Delivery",
                "QR / Quishing",
                "Medium",
                "Detected",
                100,
                [
                    item.id
                    for item in qr_urls
                ],
                "qr_detector",
                [
                    "A decoded QR URL does not "
                    "establish that its "
                    "destination is malicious."
                ],
            )
        )

    email_warning_items = _matching(
        evidence_items,
        "email_warning",
    )

    mismatch_items = [
        item
        for item in email_warning_items
        if "domain differs" in str(
            item.value
        )
    ]

    if mismatch_items:
        findings.append(
            _new_finding(
                "Email Sender-Path Mismatch",
                "Email Forensics",
                "Medium",
                "Indicator Present",
                90,
                [
                    item.id
                    for item in mismatch_items
                ],
                "email_detector",
                [
                    "Sender-path mismatches can "
                    "occur legitimately and do not "
                    "alone prove spoofing."
                ],
            )
        )

    auth_failure_items = [
        item
        for item in _matching(
            evidence_items,
            "email_authentication",
        )
        if str(
            item.value.get(
                "status",
                "",
            )
        ).lower()
        in {
            "fail",
            "softfail",
            "temperror",
            "permerror",
        }
    ]

    if auth_failure_items:
        findings.append(
            _new_finding(
                "Email Authentication Failure",
                "Email Forensics",
                "High",
                "Indicator Present",
                90,
                [
                    item.id
                    for item in auth_failure_items
                ],
                "email_detector",
                [
                    "Authentication results are "
                    "header-reported unless "
                    "explicitly independently "
                    "verified."
                ],
            )
        )

    threat_items = _matching(
        evidence_items,
        "threat_intelligence",
    )

    for item in threat_items:
        value = item.value

        if value.get("status") != "success":
            continue

        malicious = int(
            value.get(
                "malicious",
                0,
            )
            or 0
        )
        suspicious = int(
            value.get(
                "suspicious",
                0,
            )
            or 0
        )

        if malicious > 0:
            findings.append(
                _new_finding(
                    "Threat Intelligence Detection",
                    "Threat Intelligence",
                    "High",
                    "Detected",
                    98,
                    [item.id],
                    "virustotal",
                )
            )
        elif suspicious > 0:
            findings.append(
                _new_finding(
                    "Threat Intelligence Suspicion",
                    "Threat Intelligence",
                    "Medium",
                    "Indicator Present",
                    90,
                    [item.id],
                    "virustotal",
                )
            )

    urls = _matching(
        evidence_items,
        "indicator_url",
    )
    credentials = [
        item
        for item in social_items
        if item.value.get("signal")
        == "Credential Request"
    ]
    mfa = [
        item
        for item in social_items
        if item.value.get("signal")
        == "MFA Code Request"
    ]
    payments = [
        item
        for item in social_items
        if item.value.get("signal")
        == "Payment Change or Financial Pressure"
    ]
    pressure = [
        item
        for item in social_items
        if item.value.get("signal")
        in {
            "Urgency Pressure",
            "Authority or Support Impersonation",
        }
    ]

    if credentials and urls:
        findings.append(
            _new_finding(
                "Credential Phishing Pattern",
                "Phishing",
                "High",
                "Likely",
                84,
                [
                    credentials[0].id,
                    urls[0].id,
                ],
                "attack_classifier",
                [
                    "The pattern supports a "
                    "phishing hypothesis but does "
                    "not prove credential theft "
                    "occurred."
                ],
            )
        )

    if mfa and urls:
        findings.append(
            _new_finding(
                "MFA Theft Pattern",
                "Phishing",
                "High",
                "Likely",
                88,
                [
                    mfa[0].id,
                    urls[0].id,
                ],
                "attack_classifier",
                [
                    "The evidence supports an MFA "
                    "code collection hypothesis; "
                    "no account compromise is "
                    "confirmed."
                ],
            )
        )

    if payments and pressure:
        findings.append(
            _new_finding(
                "Payment Diversion Pattern",
                "Social Engineering",
                "High",
                "Likely",
                84,
                [
                    payments[0].id,
                    pressure[0].id,
                ],
                "attack_classifier",
                [
                    "Payment-pressure language "
                    "supports a diversion/fraud "
                    "hypothesis but does not prove "
                    "a transaction occurred."
                ],
            )
        )

    return _merge_findings(findings)


def findings_as_dicts(
    findings: list[AttackFinding],
) -> list[dict]:
    return [
        finding.model_dump()
        for finding in findings
    ]

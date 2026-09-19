from __future__ import annotations

from app.models import (
    AttackFinding,
    EvidenceItem,
)
from app.services.finding_rules_common import (
    matching,
    new_finding,
)

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


def classify_behavioral_findings(
    evidence_items: list[EvidenceItem],
) -> list[AttackFinding]:
    findings: list[AttackFinding] = []
    social_items = matching(
        evidence_items,
        "social_engineering",
    )

    for item in social_items:
        value = item.value
        findings.append(
            new_finding(
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
        for item in matching(
            evidence_items,
            "url_finding",
        )
        if item.value.get("type")
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
                item.value.get("type")
                == "suspicious"
                for item in url_items
            )
            else "Medium"
        )
        findings.append(
            new_finding(
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

    redirects = matching(
        evidence_items,
        "redirect_chain",
    )

    if redirects:
        findings.append(
            new_finding(
                "Redirect Chain",
                "URL Behavior",
                "Medium",
                "Detected",
                100,
                [
                    item.id
                    for item in redirects
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
        for item in matching(
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
            new_finding(
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

    urls = matching(
        evidence_items,
        "indicator_url",
    )
    signals = {
        item.value.get("signal"): item
        for item in social_items
    }

    credential = signals.get(
        "Credential Request"
    )
    mfa = signals.get(
        "MFA Code Request"
    )
    payment = signals.get(
        "Payment Change or Financial Pressure"
    )
    pressure = (
        signals.get("Urgency Pressure")
        or signals.get(
            "Authority or Support Impersonation"
        )
    )

    if credential and urls:
        findings.append(
            new_finding(
                "Credential Phishing Pattern",
                "Phishing",
                "High",
                "Likely",
                84,
                [
                    credential.id,
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
            new_finding(
                "MFA Theft Pattern",
                "Phishing",
                "High",
                "Likely",
                88,
                [
                    mfa.id,
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

    if payment and pressure:
        findings.append(
            new_finding(
                "Payment Diversion Pattern",
                "Social Engineering",
                "High",
                "Likely",
                84,
                [
                    payment.id,
                    pressure.id,
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

    return findings

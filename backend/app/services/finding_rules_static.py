from __future__ import annotations

from app.models import (
    AttackFinding,
    EvidenceItem,
)
from app.services.finding_rules_common import (
    matching,
    new_finding,
)


def classify_static_findings(
    evidence_items: list[EvidenceItem],
) -> list[AttackFinding]:
    findings: list[AttackFinding] = []

    for item in matching(
        evidence_items,
        "file_finding",
    ):
        value = item.value
        findings.append(
            new_finding(
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

    email_warnings = matching(
        evidence_items,
        "email_warning",
    )
    mismatches = [
        item
        for item in email_warnings
        if "domain differs" in str(
            item.value
        )
    ]

    if mismatches:
        findings.append(
            new_finding(
                "Email Sender-Path Mismatch",
                "Email Forensics",
                "Medium",
                "Indicator Present",
                90,
                [
                    item.id
                    for item in mismatches
                ],
                "email_detector",
                [
                    "Sender-path mismatches can "
                    "occur legitimately and do not "
                    "alone prove spoofing."
                ],
            )
        )

    auth_failures = [
        item
        for item in matching(
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

    if auth_failures:
        findings.append(
            new_finding(
                "Email Authentication Failure",
                "Email Forensics",
                "High",
                "Indicator Present",
                90,
                [
                    item.id
                    for item in auth_failures
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

    for item in matching(
        evidence_items,
        "threat_intelligence",
    ):
        value = item.value

        if value.get("status") != "success":
            continue

        malicious = int(
            value.get("malicious", 0)
            or 0
        )
        suspicious = int(
            value.get("suspicious", 0)
            or 0
        )

        if malicious > 0:
            findings.append(
                new_finding(
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
                new_finding(
                    "Threat Intelligence Suspicion",
                    "Threat Intelligence",
                    "Medium",
                    "Indicator Present",
                    90,
                    [item.id],
                    "virustotal",
                )
            )

    return findings

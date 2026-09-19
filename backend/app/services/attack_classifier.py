from __future__ import annotations

from app.models import (
    AttackFinding,
    EvidenceItem,
)
from app.services.finding_rules_behavioral import (
    classify_behavioral_findings,
)
from app.services.finding_rules_common import (
    SEVERITY_ORDER,
    STATUS_ORDER,
)
from app.services.finding_rules_static import (
    classify_static_findings,
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
    findings = [
        *classify_static_findings(
            evidence_items
        ),
        *classify_behavioral_findings(
            evidence_items
        ),
    ]

    return _merge_findings(findings)


def findings_as_dicts(
    findings: list[AttackFinding],
) -> list[dict]:
    return [
        finding.model_dump()
        for finding in findings
    ]

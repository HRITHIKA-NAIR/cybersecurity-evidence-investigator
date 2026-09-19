from __future__ import annotations

from app.models import (
    AttackFinding,
    EvidenceItem,
)

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


def matching(
    evidence_items: list[EvidenceItem],
    evidence_type: str,
) -> list[EvidenceItem]:
    return [
        item
        for item in evidence_items
        if item.type == evidence_type
    ]


def new_finding(
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

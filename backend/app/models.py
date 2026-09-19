from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal[
    "Low Risk",
    "Suspicious",
    "High Risk",
    "Inconclusive",
]
FindingStatus = Literal[
    "Detected",
    "Likely",
    "Indicator Present",
    "Requires Dynamic Analysis",
    "Not Applicable",
    "Insufficient Evidence",
]
Severity = Literal[
    "Info",
    "Low",
    "Medium",
    "High",
    "Critical",
]


class EvidenceItem(BaseModel):
    id: str
    type: str
    source: str
    value: Any
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )
    artifact_id: str | None = None
    provenance: dict = Field(
        default_factory=dict
    )


class AttackFinding(BaseModel):
    attack_type: str
    category: str
    severity: Severity
    status: FindingStatus
    confidence: int = Field(
        ge=0,
        le=100,
    )
    evidence_ids: list[str]
    detector: str
    limitations: list[str] = Field(
        default_factory=list
    )


class AttackChainStage(BaseModel):
    order: int = Field(ge=1)
    stage: str
    value: str
    confidence: int = Field(
        ge=0,
        le=100,
    )
    evidence_ids: list[str]


class AssessmentResult(BaseModel):
    threat_score: int = Field(
        ge=0,
        le=100,
    )
    verdict: Verdict
    confidence: int = Field(
        ge=0,
        le=100,
    )
    reasoning: str
    insufficient_evidence: bool = False


class ChallengeResult(BaseModel):
    revised_verdict: Verdict
    revised_confidence: int = Field(
        ge=0,
        le=100,
    )
    counter_evidence: list[str] = Field(
        default_factory=list
    )
    reasoning: str
    conclusion_changed: bool = False

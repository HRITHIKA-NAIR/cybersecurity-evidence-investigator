from __future__ import annotations

from app.models import EvidenceItem


class EvidenceBuilder:
    def __init__(self):
        self.items: list[EvidenceItem] = []

    def add(
        self,
        evidence_type: str,
        source: str,
        value,
        *,
        confidence: float = 1.0,
        artifact_id: str | None = None,
        summary: str | None = None,
        provenance: dict | None = None,
    ) -> str:
        evidence_id = (
            f"ev-{len(self.items) + 1:04d}"
        )
        metadata = dict(
            provenance or {}
        )

        if summary:
            metadata["summary"] = summary

        self.items.append(
            EvidenceItem(
                id=evidence_id,
                type=evidence_type,
                source=source,
                value=value,
                confidence=confidence,
                artifact_id=artifact_id,
                provenance=metadata,
            )
        )
        return evidence_id

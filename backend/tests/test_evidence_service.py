from app.services.evidence_service import (
    build_evidence_items,
)


def test_normalizes_named_evidence_sources():
    items = build_evidence_items(
        content="Urgent https://example.test",
        indicators={
            "urls": [
                "https://example.test"
            ],
            "domains": [
                "example.test"
            ],
            "emails": [],
        },
        url_analysis=[],
        threat_intelligence=[
            {
                "domain": "example.test",
                "status": "unknown",
                "message": "Not found",
            }
        ],
        social_signals=[
            {
                "signal": "Urgency Pressure",
                "category": "Social Engineering",
                "severity": "Medium",
                "status": "Indicator Present",
                "confidence": 82,
                "message": (
                    "Urgency Pressure language "
                    "was detected."
                ),
            }
        ],
    )

    ids = [item.id for item in items]
    sources = {
        item.source
        for item in items
    }

    assert len(ids) == len(set(ids))
    assert "indicator_extractor" in sources
    assert "virustotal" in sources
    assert "social_engineering" in sources


def test_file_finding_keeps_artifact_provenance():
    items = build_evidence_items(
        content="",
        indicators={
            "urls": [],
            "domains": [],
            "emails": [],
        },
        url_analysis=[],
        threat_intelligence=[],
        file_info={
            "filename": "invoice.pdf.zip",
            "extension": ".zip",
            "size_bytes": 10,
            "sha256": "abc",
        },
        file_analysis={
            "findings": [
                {
                    "attack_type": "Double Extension",
                    "category": "Filename Deception",
                    "severity": "Medium",
                    "status": "Indicator Present",
                    "confidence": 95,
                    "evidence": ["double extension"],
                }
            ],
            "qr": {
                "status": "completed",
                "payloads": [],
            },
        },
    )

    finding = next(
        item
        for item in items
        if item.type == "file_finding"
    )

    assert finding.artifact_id == "artifact-1"

from app.models import (
    AttackFinding,
    EvidenceItem,
)
from app.services.attack_chain import (
    build_attack_chain,
)


def test_builds_supported_email_qr_credential_chain():
    evidence = [
        EvidenceItem(
            id="ev-0001",
            type="email_sender",
            source="email_parser",
            value={
                "address": "sender@example.test",
            },
        ),
        EvidenceItem(
            id="ev-0002",
            type="artifact",
            source="ingestion",
            value={
                "filename": "message.eml",
                "extension": ".eml",
            },
        ),
        EvidenceItem(
            id="ev-0003",
            type="qr_payload",
            source="qr_detector",
            value={
                "payload": "https://example.test/login",
                "source": "office:image1.png",
            },
        ),
        EvidenceItem(
            id="ev-0004",
            type="indicator_url",
            source="indicator_extractor",
            value="https://example.test/login",
        ),
        EvidenceItem(
            id="ev-0005",
            type="social_engineering",
            source="social_engineering",
            value={
                "signal": "Credential Request",
            },
        ),
    ]
    findings = [
        AttackFinding(
            attack_type="QR Link Delivery",
            category="QR / Quishing",
            severity="Medium",
            status="Detected",
            confidence=100,
            evidence_ids=["ev-0003"],
            detector="qr_detector",
        ),
        AttackFinding(
            attack_type="Credential Phishing Pattern",
            category="Phishing",
            severity="High",
            status="Likely",
            confidence=84,
            evidence_ids=[
                "ev-0005",
                "ev-0004",
            ],
            detector="attack_classifier",
        ),
    ]

    chain = build_attack_chain(
        evidence,
        findings,
    )
    stages = [
        stage.stage
        for stage in chain
    ]

    assert stages == sorted(
        stages,
        key={
            "Source": 1,
            "Delivery Technique": 2,
            "Object": 3,
            "Embedded Object": 4,
            "Destination": 5,
            "URL Behavior": 6,
            "Website / Authentication Technique": 7,
            "Payload / Objective": 8,
            "Potential Impact": 9,
        }.get,
    )
    assert "Source" in stages
    assert "Delivery Technique" in stages
    assert "Embedded Object" in stages
    assert "Destination" in stages
    assert "Potential Impact" in stages


def test_omits_unsupported_unknown_stages():
    evidence = [
        EvidenceItem(
            id="ev-0001",
            type="indicator_url",
            source="indicator_extractor",
            value="https://example.test",
        )
    ]

    chain = build_attack_chain(
        evidence,
        [],
    )

    assert [
        stage.stage
        for stage in chain
    ] == ["Destination"]

from app.models import EvidenceItem
from app.services.attack_classifier import (
    classify_attack_findings,
)


def _types(findings):
    return {
        finding.attack_type
        for finding in findings
    }


def test_returns_multiple_findings():
    evidence = [
        EvidenceItem(
            id="ev-0001",
            type="social_engineering",
            source="social_engineering",
            value={
                "signal": "Credential Request",
                "category": "Social Engineering",
                "severity": "High",
                "status": "Indicator Present",
                "confidence": 90,
            },
        ),
        EvidenceItem(
            id="ev-0002",
            type="indicator_url",
            source="indicator_extractor",
            value="https://example.test/login",
        ),
        EvidenceItem(
            id="ev-0003",
            type="url_finding",
            source="url_detector",
            value={
                "url": "https://example.test/login",
                "type": "suspicious",
                "message": (
                    "URL contains user-info "
                    "before the hostname"
                ),
            },
        ),
    ]

    findings = classify_attack_findings(
        evidence
    )
    types = _types(findings)

    assert "Credential Request" in types
    assert "Credential Phishing Pattern" in types
    assert "URL Deception Indicators" in types


def test_qr_link_is_delivery_not_malware_claim():
    evidence = [
        EvidenceItem(
            id="ev-0001",
            type="qr_payload",
            source="qr_detector",
            value={
                "payload": "https://example.test",
                "source": "uploaded-image",
            },
        )
    ]

    findings = classify_attack_findings(
        evidence
    )
    qr = next(
        finding
        for finding in findings
        if finding.attack_type
        == "QR Link Delivery"
    )

    assert qr.status == "Detected"
    assert qr.category == "QR / Quishing"
    assert qr.limitations


def test_virustotal_malicious_result_is_detected():
    evidence = [
        EvidenceItem(
            id="ev-0001",
            type="threat_intelligence",
            source="virustotal",
            value={
                "domain": "example.test",
                "status": "success",
                "malicious": 3,
                "suspicious": 0,
            },
        )
    ]

    findings = classify_attack_findings(
        evidence
    )

    assert (
        "Threat Intelligence Detection"
        in _types(findings)
    )


def test_unknown_threat_intel_does_not_create_finding():
    evidence = [
        EvidenceItem(
            id="ev-0001",
            type="threat_intelligence",
            source="virustotal",
            value={
                "domain": "example.test",
                "status": "unknown",
            },
        )
    ]

    assert (
        classify_attack_findings(
            evidence
        )
        == []
    )

from app.services import investigation_service


def test_investigation_returns_structured_v2_outputs(
    monkeypatch,
):
    monkeypatch.setattr(
        investigation_service,
        "investigate_url",
        lambda url: {
            "url": url,
            "normalized_url": url,
            "hostname": "example.test",
            "scheme": "https",
            "registered_domain": "example.test",
            "subdomain": "",
            "findings": [
                {
                    "type": "positive",
                    "message": "URL uses HTTPS",
                }
            ],
            "redirect_analysis": {
                "status": "completed",
                "hops": [],
                "redirect_count": 0,
            },
        },
    )
    monkeypatch.setattr(
        investigation_service,
        "gather_threat_intelligence",
        lambda indicators, file_info=None: [
            {
                "domain": "example.test",
                "status": "success",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 5,
                "undetected": 0,
                "reputation": 0,
            }
        ],
    )
    monkeypatch.setattr(
        investigation_service,
        "analyze_evidence",
        lambda *args, **kwargs: {
            "status": "success",
            "threat_score": 40,
            "verdict": "Suspicious",
            "confidence": 80,
            "reasoning": "Grounded test result.",
            "insufficient_evidence": False,
        },
    )
    monkeypatch.setattr(
        investigation_service,
        "save_investigation",
        lambda *args, **kwargs: 42,
    )

    result = (
        investigation_service.run_investigation(
            (
                "Urgent: verify your account at "
                "https://example.test and enter "
                "your password."
            ),
            user_id=1,
        )
    )

    attack_types = {
        finding["attack_type"]
        for finding in result[
            "attack_findings"
        ]
    }

    assert result["investigation_id"] == 42
    assert result["evidence_items"]
    assert "Credential Request" in attack_types
    assert (
        "Credential Phishing Pattern"
        in attack_types
    )
    assert result["attack_chain"]
    assert (
        result["stages"][
            "classify_attacks"
        ]
        is True
    )

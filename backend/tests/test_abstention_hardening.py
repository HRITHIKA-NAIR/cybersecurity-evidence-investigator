from app.tools import ai_analysis


def _low_risk_result():
    return {
        "threat_score": 5,
        "verdict": "Low Risk",
        "confidence": 80,
        "reasoning": "test",
        "insufficient_evidence": False,
    }


def test_unknown_hash_does_not_defeat_abstention(
    monkeypatch,
):
    monkeypatch.setattr(
        ai_analysis,
        "available",
        lambda: True,
    )
    monkeypatch.setattr(
        ai_analysis,
        "generate_json",
        lambda *args, **kwargs: (
            _low_risk_result()
        ),
    )

    result = ai_analysis.analyze_evidence(
        "ordinary note",
        {
            "urls": [],
            "domains": [],
            "emails": [],
        },
        [],
        [
            {
                "hash": "a" * 64,
                "status": "unknown",
            }
        ],
    )

    assert (
        result["verdict"]
        == "Inconclusive"
    )
    assert result["threat_score"] == 0
    assert (
        result["insufficient_evidence"]
        is True
    )


def test_header_routing_ip_alone_does_not_prove_safety(
    monkeypatch,
):
    monkeypatch.setattr(
        ai_analysis,
        "available",
        lambda: True,
    )
    monkeypatch.setattr(
        ai_analysis,
        "generate_json",
        lambda *args, **kwargs: (
            _low_risk_result()
        ),
    )

    result = ai_analysis.analyze_evidence(
        "ordinary message",
        {
            "urls": [],
            "domains": [],
            "emails": [],
        },
        [],
        [],
        {
            "originating_ip": "8.8.8.8",
            "warnings": [],
            "authentication": {
                "spf": "not_reported",
                "dkim": "not_reported",
                "dmarc": "not_reported",
            },
            "routing_intelligence": {
                "status": "success",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 3,
            },
        },
    )

    assert (
        result["verdict"]
        == "Inconclusive"
    )

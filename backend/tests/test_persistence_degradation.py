from app.persistence.config import (
    DatabaseOperationError,
)
from app.services import investigation_service


def test_investigation_survives_database_write_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        investigation_service,
        "gather_threat_intelligence",
        lambda indicators, file_info=None: [],
    )
    monkeypatch.setattr(
        investigation_service,
        "investigate_url",
        lambda url: {
            "url": url,
            "normalized_url": url,
            "findings": [],
            "redirect_analysis": {
                "status": "completed",
                "hops": [],
                "redirect_count": 0,
            },
        },
    )
    monkeypatch.setattr(
        investigation_service,
        "analyze_evidence",
        lambda *args, **kwargs: {
            "status": "success",
            "threat_score": 30,
            "verdict": "Suspicious",
            "confidence": 70,
            "reasoning": "test",
            "insufficient_evidence": False,
        },
    )

    def fail_save(*args, **kwargs):
        raise DatabaseOperationError(
            "database unavailable"
        )

    monkeypatch.setattr(
        investigation_service,
        "save_investigation",
        fail_save,
    )

    result = (
        investigation_service.run_investigation(
            "Urgent account verification.",
            user_id=1,
        )
    )

    assert result["status"] == "completed"
    assert (
        result["investigation_id"]
        is None
    )
    assert (
        result["persistence"]["status"]
        == "unavailable"
    )
    assert result["attack_findings"]

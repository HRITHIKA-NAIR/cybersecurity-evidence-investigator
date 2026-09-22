import pytest
from pydantic import ValidationError

from app.models import ChallengeResult


def test_challenge_schema_includes_v21_fields():
    result = ChallengeResult(
        revised_threat_score=25,
        revised_verdict="Suspicious",
        revised_confidence=65,
        counter_evidence=[
            "No malicious detections."
        ],
        uncertainty=[
            "Destination behavior is unknown."
        ],
        reasoning="Evidence-grounded review.",
        conclusion_changed=True,
    )

    assert result.revised_threat_score == 25
    assert result.uncertainty


def test_challenge_schema_rejects_missing_revised_score():
    with pytest.raises(
        ValidationError
    ):
        ChallengeResult(
            revised_verdict="Suspicious",
            revised_confidence=65,
            reasoning="Missing score.",
        )

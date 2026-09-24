from __future__ import annotations

from app.database import (
    DatabaseOperationError,
    get_investigation,
    save_challenge,
)
from app.tools.ai_analysis import (
    challenge_assessment,
)


def run_challenge(
    investigation_id: int,
    *, owner_id: str | None = None,
) -> dict | None:
    investigation = get_investigation(
        investigation_id, owner_id=owner_id
    )

    if not investigation:
        return None

    original_assessment = {
        "threat_score": investigation[
            "threat_score"
        ],
        "verdict": investigation[
            "verdict"
        ],
        "confidence": investigation[
            "confidence"
        ],
        "reasoning": investigation[
            "reasoning"
        ],
    }

    result = challenge_assessment(
        investigation["content"],
        investigation["indicators"],
        investigation["url_analysis"],
        investigation[
            "threat_intelligence"
        ],
        original_assessment,
        investigation.get(
            "email_analysis"
        ),
        investigation.get(
            "file_analysis"
        ),
        investigation.get(
            "evidence_items"
        ),
        investigation.get(
            "attack_findings"
        ),
        investigation.get(
            "attack_chain"
        ),
    )

    try:
        save_challenge(
            investigation_id,
            result,
            owner_id=owner_id,
        )
        result["persistence"] = {
            "status": "saved",
            "message": None,
        }
    except DatabaseOperationError:
        result["persistence"] = {
            "status": "unavailable",
            "message": (
                "Challenge completed, but the "
                "revised result could not be "
                "saved to persistent history."
            ),
        }

    return result

import os
import uuid

import pytest

from app.database import (
    get_investigation,
    init_database,
    save_challenge,
    save_investigation,
)
from app.persistence.pool import get_pool
from app.persistence.users import create_user


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1"
    or not os.getenv("DATABASE_URL"),
    reason=(
        "Live PostgreSQL integration test is opt-in."
    ),
)


def test_postgres_round_trip():
    init_database()
    token = str(uuid.uuid4())

    test_user = create_user(
        f"integration-{token}@test.local",
        "not-a-real-hash",
    )
    user_id = test_user["id"]

    investigation_id = save_investigation(
        "integration " + token,
        {
            "urls": [],
            "domains": [],
            "emails": [],
        },
        [],
        [],
        {
            "threat_score": 20,
            "verdict": "Suspicious",
            "confidence": 70,
            "reasoning": "integration test",
            "insufficient_evidence": False,
        },
        user_id=user_id,
        evidence_items=[
            {
                "id": "ev-0001",
                "type": "test",
                "source": "integration",
                "value": {
                    "token": token,
                },
                "confidence": 1.0,
                "artifact_id": None,
                "provenance": {},
            }
        ],
        attack_findings=[
            {
                "attack_type": "Test Finding",
                "category": "Test",
                "severity": "Low",
                "status": "Indicator Present",
                "confidence": 70,
                "evidence_ids": [
                    "ev-0001"
                ],
                "detector": "integration",
                "limitations": [],
            }
        ],
        attack_chain=[
            {
                "order": 1,
                "stage": "Source",
                "value": "integration",
                "confidence": 70,
                "evidence_ids": [
                    "ev-0001"
                ],
            }
        ],
    )

    try:
        save_challenge(
            investigation_id,
            {
                "status": "success",
                "revised_threat_score": 15,
                "revised_verdict": "Suspicious",
                "revised_confidence": 60,
                "counter_evidence": [],
                "uncertainty": [
                    "Synthetic integration case."
                ],
                "reasoning": "integration challenge",
                "conclusion_changed": False,
            },
            user_id=user_id,
        )

        stored = get_investigation(
            investigation_id,
            user_id=user_id,
        )

        assert stored is not None
        assert stored["evidence_items"][0][
            "id"
        ] == "ev-0001"
        assert stored["attack_findings"][0][
            "evidence_ids"
        ] == ["ev-0001"]
        assert stored["attack_chain"][0][
            "stage"
        ] == "Source"
        assert (
            stored["challenge_result"][
                "revised_threat_score"
            ]
            == 15
        )
        assert (
            stored["challenge_result"][
                "revised_confidence"
            ]
            == 60
        )
    finally:
        # Deleting the user (a table with no RLS) cascades to the
        # investigation and every child row via ON DELETE CASCADE, so
        # there is no need to delete investigations directly - and a
        # direct DELETE on investigations from a connection with no RLS
        # context set would delete nothing anyway, now that RLS is
        # enforced.
        pool = get_pool()

        with pool.connection() as connection:
            connection.execute(
                """
                DELETE FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            connection.commit()

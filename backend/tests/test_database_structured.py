from app import database


def test_persists_structured_v2_evidence(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "test.db",
    )
    database.init_db()

    investigation_id = (
        database.save_investigation(
            "test content",
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
                "reasoning": "test",
                "insufficient_evidence": False,
            },
            evidence_items=[
                {
                    "id": "ev-0001",
                    "type": "test",
                    "source": "unit",
                    "value": "evidence",
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
                    "evidence_ids": ["ev-0001"],
                    "detector": "unit",
                    "limitations": [],
                }
            ],
            attack_chain=[
                {
                    "order": 1,
                    "stage": "Source",
                    "value": "test",
                    "confidence": 70,
                    "evidence_ids": ["ev-0001"],
                }
            ],
        )
    )

    stored = database.get_investigation(
        investigation_id
    )

    assert stored["evidence_items"][0][
        "id"
    ] == "ev-0001"
    assert stored["attack_findings"][0][
        "attack_type"
    ] == "Test Finding"
    assert stored["attack_chain"][0][
        "stage"
    ] == "Source"

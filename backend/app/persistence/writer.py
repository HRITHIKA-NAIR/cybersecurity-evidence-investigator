from __future__ import annotations

from psycopg.types.json import Jsonb

from app.persistence.config import (
    DatabaseOperationError,
)
from app.persistence.pool import get_pool
from app.persistence.write_evidence import (
    insert_chain,
    insert_evidence,
    insert_findings,
)
from app.persistence.write_metadata import (
    insert_artifact,
    insert_derived_artifacts,
    insert_email,
    insert_redirects,
    parse_timestamp,
)


def _input_type(
    file_info: dict | None,
) -> str:
    if not file_info:
        return "text"

    if file_info.get("extension") == ".eml":
        return "email"

    return "file"


def save_investigation(
    content,
    indicators,
    url_analysis,
    threat_intelligence,
    ai_result,
    *,
    file_info=None,
    email_analysis=None,
    file_analysis=None,
    evidence_items=None,
    attack_findings=None,
    attack_chain=None,
    legacy_source_id=None,
    created_at=None,
):
    pool = get_pool()

    try:
        with pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    INSERT INTO investigations (
                        legacy_source_id,
                        input_type,
                        content,
                        indicators,
                        url_analysis,
                        threat_intelligence,
                        file_analysis,
                        threat_score,
                        verdict,
                        confidence,
                        reasoning,
                        insufficient_evidence,
                        created_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        COALESCE(%s, NOW())
                    )
                    RETURNING id
                    """,
                    (
                        legacy_source_id,
                        _input_type(file_info),
                        content,
                        Jsonb(indicators),
                        Jsonb(url_analysis),
                        Jsonb(
                            threat_intelligence
                        ),
                        (
                            Jsonb(file_analysis)
                            if file_analysis
                            is not None
                            else None
                        ),
                        int(
                            ai_result[
                                "threat_score"
                            ]
                        ),
                        ai_result["verdict"],
                        int(
                            ai_result[
                                "confidence"
                            ]
                        ),
                        ai_result["reasoning"],
                        bool(
                            ai_result[
                                "insufficient_evidence"
                            ]
                        ),
                        parse_timestamp(
                            created_at
                        ),
                    ),
                ).fetchone()

                investigation_id = row["id"]
                structured_evidence = (
                    evidence_items or []
                )

                insert_artifact(
                    connection,
                    investigation_id,
                    file_info,
                )
                insert_derived_artifacts(
                    connection,
                    investigation_id,
                    structured_evidence,
                )
                evidence_map = (
                    insert_evidence(
                        connection,
                        investigation_id,
                        structured_evidence,
                    )
                )
                insert_findings(
                    connection,
                    investigation_id,
                    attack_findings or [],
                    evidence_map,
                )
                insert_chain(
                    connection,
                    investigation_id,
                    attack_chain or [],
                )
                insert_email(
                    connection,
                    investigation_id,
                    email_analysis,
                )
                insert_redirects(
                    connection,
                    investigation_id,
                    url_analysis,
                )

                return investigation_id

    except DatabaseOperationError:
        raise
    except Exception as exc:
        raise DatabaseOperationError(
            "Could not persist investigation."
        ) from exc


def save_challenge(
    investigation_id,
    challenge_result,
):
    pool = get_pool()

    try:
        with pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO challenge_results (
                        investigation_id,
                        revised_threat_score,
                        revised_verdict,
                        revised_confidence,
                        counter_evidence,
                        uncertainty,
                        reasoning,
                        conclusion_changed,
                        raw_result
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (
                        investigation_id
                    )
                    DO UPDATE SET
                        revised_threat_score =
                            EXCLUDED.revised_threat_score,
                        revised_verdict =
                            EXCLUDED.revised_verdict,
                        revised_confidence =
                            EXCLUDED.revised_confidence,
                        counter_evidence =
                            EXCLUDED.counter_evidence,
                        uncertainty =
                            EXCLUDED.uncertainty,
                        reasoning =
                            EXCLUDED.reasoning,
                        conclusion_changed =
                            EXCLUDED.conclusion_changed,
                        raw_result =
                            EXCLUDED.raw_result,
                        created_at = NOW()
                    """,
                    (
                        investigation_id,
                        int(
                            challenge_result[
                                "revised_threat_score"
                            ]
                        ),
                        challenge_result[
                            "revised_verdict"
                        ],
                        int(
                            challenge_result[
                                "revised_confidence"
                            ]
                        ),
                        Jsonb(
                            challenge_result.get(
                                "counter_evidence",
                                [],
                            )
                        ),
                        Jsonb(
                            challenge_result.get(
                                "uncertainty",
                                [],
                            )
                        ),
                        challenge_result[
                            "reasoning"
                        ],
                        bool(
                            challenge_result.get(
                                "conclusion_changed",
                                False,
                            )
                        ),
                        Jsonb(challenge_result),
                    ),
                )
    except Exception as exc:
        raise DatabaseOperationError(
            "Could not persist challenge result."
        ) from exc

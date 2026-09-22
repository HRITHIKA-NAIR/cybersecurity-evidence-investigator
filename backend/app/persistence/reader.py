from __future__ import annotations

from collections import defaultdict

from app.persistence.config import (
    DatabaseOperationError,
)
from app.persistence.pool import get_pool


def _query_related(
    connection,
    investigation_ids: list[int],
) -> dict:
    if not investigation_ids:
        return {
            "artifacts": {},
            "evidence": defaultdict(list),
            "findings": defaultdict(list),
            "chain": defaultdict(list),
            "email": {},
            "challenge": {},
        }

    artifacts = {}

    for row in connection.execute(
        """
        SELECT
            investigation_id,
            artifact_key,
            metadata
        FROM artifacts
        WHERE investigation_id = ANY(%s)
        ORDER BY
            investigation_id,
            (artifact_key = 'artifact-1') DESC,
            id
        """,
        (investigation_ids,),
    ).fetchall():
        artifacts.setdefault(
            row["investigation_id"],
            row["metadata"],
        )

    evidence = defaultdict(list)
    evidence_rows = connection.execute(
        """
        SELECT
            id AS database_id,
            investigation_id,
            evidence_key,
            type,
            source,
            value,
            confidence,
            artifact_ref,
            provenance
        FROM evidence_items
        WHERE investigation_id = ANY(%s)
        ORDER BY id
        """,
        (investigation_ids,),
    ).fetchall()

    for row in evidence_rows:
        evidence[
            row["investigation_id"]
        ].append(
            {
                "id": row["evidence_key"],
                "type": row["type"],
                "source": row["source"],
                "value": row["value"],
                "confidence": row[
                    "confidence"
                ],
                "artifact_id": row[
                    "artifact_ref"
                ],
                "provenance": (
                    row["provenance"]
                    or {}
                ),
            }
        )

    finding_evidence = defaultdict(list)

    for row in connection.execute(
        """
        SELECT
            f.investigation_id,
            fe.finding_id,
            e.evidence_key
        FROM finding_evidence fe
        JOIN attack_findings f
          ON f.id = fe.finding_id
        JOIN evidence_items e
          ON e.id = fe.evidence_item_id
        WHERE f.investigation_id = ANY(%s)
        ORDER BY fe.finding_id, e.id
        """,
        (investigation_ids,),
    ).fetchall():
        finding_evidence[
            row["finding_id"]
        ].append(
            row["evidence_key"]
        )

    findings = defaultdict(list)

    for row in connection.execute(
        """
        SELECT
            id,
            investigation_id,
            attack_type,
            category,
            severity,
            status,
            confidence,
            detector,
            limitations
        FROM attack_findings
        WHERE investigation_id = ANY(%s)
        ORDER BY id
        """,
        (investigation_ids,),
    ).fetchall():
        findings[
            row["investigation_id"]
        ].append(
            {
                "attack_type": (
                    row["attack_type"]
                ),
                "category": row["category"],
                "severity": row["severity"],
                "status": row["status"],
                "confidence": row[
                    "confidence"
                ],
                "evidence_ids": (
                    finding_evidence[
                        row["id"]
                    ]
                ),
                "detector": row["detector"],
                "limitations": (
                    row["limitations"]
                    or []
                ),
            }
        )

    chain = defaultdict(list)

    for row in connection.execute(
        """
        SELECT
            investigation_id,
            stage_order,
            stage,
            value,
            confidence,
            evidence_ids
        FROM attack_chain_stages
        WHERE investigation_id = ANY(%s)
        ORDER BY investigation_id, stage_order
        """,
        (investigation_ids,),
    ).fetchall():
        chain[
            row["investigation_id"]
        ].append(
            {
                "order": row["stage_order"],
                "stage": row["stage"],
                "value": row["value"],
                "confidence": row[
                    "confidence"
                ],
                "evidence_ids": (
                    row["evidence_ids"]
                    or []
                ),
            }
        )

    email = {
        row["investigation_id"]: (
            row["raw_metadata"]
        )
        for row in connection.execute(
            """
            SELECT
                investigation_id,
                raw_metadata
            FROM email_metadata
            WHERE investigation_id = ANY(%s)
            """,
            (investigation_ids,),
        ).fetchall()
    }

    challenge = {
        row["investigation_id"]: (
            row["raw_result"]
        )
        for row in connection.execute(
            """
            SELECT
                investigation_id,
                raw_result
            FROM challenge_results
            WHERE investigation_id = ANY(%s)
            """,
            (investigation_ids,),
        ).fetchall()
    }

    return {
        "artifacts": artifacts,
        "evidence": evidence,
        "findings": findings,
        "chain": chain,
        "email": email,
        "challenge": challenge,
    }


def _hydrate(
    rows: list[dict],
    related: dict,
) -> list[dict]:
    results = []

    for row in rows:
        investigation_id = row["id"]

        results.append(
            {
                "id": investigation_id,
                "investigation_id": (
                    investigation_id
                ),
                "input_type": (
                    row["input_type"]
                ),
                "content": row["content"],
                "indicators": (
                    row["indicators"]
                    or {}
                ),
                "url_analysis": (
                    row["url_analysis"]
                    or []
                ),
                "threat_intelligence": (
                    row[
                        "threat_intelligence"
                    ]
                    or []
                ),
                "file_info": (
                    related[
                        "artifacts"
                    ].get(
                        investigation_id
                    )
                ),
                "file_analysis": (
                    row["file_analysis"]
                ),
                "email_analysis": (
                    related["email"].get(
                        investigation_id
                    )
                ),
                "evidence_items": list(
                    related[
                        "evidence"
                    ].get(
                        investigation_id,
                        [],
                    )
                ),
                "attack_findings": list(
                    related[
                        "findings"
                    ].get(
                        investigation_id,
                        [],
                    )
                ),
                "attack_chain": list(
                    related["chain"].get(
                        investigation_id,
                        [],
                    )
                ),
                "threat_score": (
                    row["threat_score"]
                ),
                "verdict": row["verdict"],
                "confidence": (
                    row["confidence"]
                ),
                "reasoning": (
                    row["reasoning"]
                ),
                "insufficient_evidence": bool(
                    row[
                        "insufficient_evidence"
                    ]
                ),
                "challenge_result": (
                    related[
                        "challenge"
                    ].get(
                        investigation_id
                    )
                ),
                "created_at": (
                    row["created_at"]
                ),
            }
        )

    return results


def _load(
    *,
    investigation_id: int | None = None,
    limit: int = 10,
) -> list[dict]:
    pool = get_pool()

    try:
        with pool.connection() as connection:
            if investigation_id is not None:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM investigations
                    WHERE id = %s
                    """,
                    (investigation_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM investigations
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (
                        max(
                            1,
                            min(limit, 100),
                        ),
                    ),
                ).fetchall()

            ids = [
                row["id"]
                for row in rows
            ]
            related = _query_related(
                connection,
                ids,
            )

        return _hydrate(
            rows,
            related,
        )

    except Exception as exc:
        raise DatabaseOperationError(
            "Could not read investigation history."
        ) from exc


def get_investigation(
    investigation_id: int,
) -> dict | None:
    rows = _load(
        investigation_id=investigation_id
    )

    return rows[0] if rows else None


def get_investigations(
    limit: int = 10,
) -> list[dict]:
    return _load(limit=limit)

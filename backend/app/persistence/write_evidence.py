from __future__ import annotations

from psycopg.types.json import Jsonb


def insert_evidence(
    connection,
    investigation_id: int,
    evidence_items: list[dict],
) -> dict[str, int]:
    ids: dict[str, int] = {}

    for item in evidence_items:
        row = connection.execute(
            """
            INSERT INTO evidence_items (
                investigation_id,
                evidence_key,
                type,
                source,
                value,
                confidence,
                artifact_ref,
                provenance
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            RETURNING id
            """,
            (
                investigation_id,
                item["id"],
                item["type"],
                item["source"],
                Jsonb(item.get("value")),
                float(
                    item.get(
                        "confidence",
                        1.0,
                    )
                ),
                item.get("artifact_id"),
                Jsonb(
                    item.get(
                        "provenance",
                        {},
                    )
                ),
            ),
        ).fetchone()
        ids[item["id"]] = row["id"]

    return ids


def insert_findings(
    connection,
    investigation_id: int,
    findings: list[dict],
    evidence_ids: dict[str, int],
) -> None:
    for finding in findings:
        row = connection.execute(
            """
            INSERT INTO attack_findings (
                investigation_id,
                attack_type,
                category,
                severity,
                status,
                confidence,
                detector,
                limitations
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            RETURNING id
            """,
            (
                investigation_id,
                finding["attack_type"],
                finding["category"],
                finding["severity"],
                finding["status"],
                int(
                    finding["confidence"]
                ),
                finding["detector"],
                Jsonb(
                    finding.get(
                        "limitations",
                        [],
                    )
                ),
            ),
        ).fetchone()

        for evidence_key in finding.get(
            "evidence_ids",
            [],
        ):
            evidence_id = evidence_ids.get(
                evidence_key
            )

            if evidence_id is None:
                continue

            connection.execute(
                """
                INSERT INTO finding_evidence (
                    finding_id,
                    evidence_item_id
                )
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    row["id"],
                    evidence_id,
                ),
            )


def insert_chain(
    connection,
    investigation_id: int,
    attack_chain: list[dict],
) -> None:
    for stage in attack_chain:
        connection.execute(
            """
            INSERT INTO attack_chain_stages (
                investigation_id,
                stage_order,
                stage,
                value,
                confidence,
                evidence_ids
            )
            VALUES (
                %s, %s, %s, %s, %s, %s
            )
            """,
            (
                investigation_id,
                int(stage["order"]),
                stage["stage"],
                stage["value"],
                int(stage["confidence"]),
                Jsonb(
                    stage.get(
                        "evidence_ids",
                        [],
                    )
                ),
            ),
        )

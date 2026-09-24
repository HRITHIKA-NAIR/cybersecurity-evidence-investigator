from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from uuid import UUID
from pathlib import Path

BACKEND_ROOT = (
    Path(__file__).resolve().parents[1]
)

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(BACKEND_ROOT),
    )

from app.database import (  # noqa: E402
    DatabaseOperationError,
    init_database,
    save_challenge,
    save_investigation,
)


def _json_value(
    row: sqlite3.Row,
    field: str,
    default,
):
    if field not in row.keys():
        return default

    value = row[field]

    if not value:
        return default

    try:
        return json.loads(value)
    except (
        TypeError,
        json.JSONDecodeError,
    ):
        return default


def migrate(
    sqlite_path: Path,
    owner_id: str,
) -> tuple[int, int, int]:
    init_database()

    source = sqlite3.connect(
        sqlite_path
    )
    source.row_factory = sqlite3.Row
    migrated = 0
    skipped = 0
    challenge_skipped = 0

    try:
        rows = source.execute(
            """
            SELECT *
            FROM investigations
            ORDER BY id
            """
        ).fetchall()

        for row in rows:
            ai_result = {
                "threat_score": row[
                    "threat_score"
                ],
                "verdict": row["verdict"],
                "confidence": row[
                    "confidence"
                ],
                "reasoning": row[
                    "reasoning"
                ],
                "insufficient_evidence": bool(
                    row[
                        "insufficient_evidence"
                    ]
                ),
            }

            try:
                new_id = save_investigation(
                    row["content"],
                    _json_value(
                        row,
                        "indicators",
                        {},
                    ),
                    _json_value(
                        row,
                        "url_analysis",
                        [],
                    ),
                    _json_value(
                        row,
                        "threat_intelligence",
                        [],
                    ),
                    ai_result,
                    email_analysis=_json_value(
                        row,
                        "email_analysis",
                        None,
                    ),
                    file_analysis=_json_value(
                        row,
                        "file_analysis",
                        None,
                    ),
                    evidence_items=_json_value(
                        row,
                        "evidence_items",
                        [],
                    ),
                    attack_findings=_json_value(
                        row,
                        "attack_findings",
                        [],
                    ),
                    attack_chain=_json_value(
                        row,
                        "attack_chain",
                        [],
                    ),
                    legacy_source_id=row["id"],
                    created_at=row["created_at"],
                    owner_id=owner_id,
                )
                migrated += 1

                challenge = _json_value(
                    row,
                    "challenge_result",
                    None,
                )

                if challenge:
                    if (
                        "revised_threat_score"
                        not in challenge
                        or "uncertainty"
                        not in challenge
                    ):
                        challenge_skipped += 1
                    else:
                        try:
                            save_challenge(
                                new_id,
                                challenge,
                                owner_id=owner_id,
                            )
                        except DatabaseOperationError:
                            challenge_skipped += 1

            except DatabaseOperationError:
                skipped += 1

    finally:
        source.close()

    return (
        migrated,
        skipped,
        challenge_skipped,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "One-time migration of legacy "
            "Investigator V1 SQLite history "
            "into the configured PostgreSQL "
            "database."
        )
    )
    parser.add_argument(
        "sqlite_path",
        nargs="?",
        default="investigations.db",
    )
    parser.add_argument("--owner-id", required=True, type=UUID, help="Verified owner UUID for this single-owner legacy database. Never assign a multi-user dump to one account.")
    args = parser.parse_args()

    path = Path(args.sqlite_path)

    if not path.exists():
        raise SystemExit(
            f"SQLite database not found: {path}"
        )

    (
        migrated,
        skipped,
        challenge_skipped,
    ) = migrate(path, str(args.owner_id))

    print(
        "Migration complete. "
        f"Migrated: {migrated}. "
        f"Investigations skipped: {skipped}. "
        "Challenge results skipped: "
        f"{challenge_skipped}."
    )


if __name__ == "__main__":
    main()

import json
import sqlite3
from pathlib import Path

DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "investigations.db"
)
JSON_FIELDS = (
    "indicators",
    "url_analysis",
    "threat_intelligence",
    "email_analysis",
    "file_analysis",
    "evidence_items",
    "attack_findings",
    "attack_chain",
    "challenge_result",
)


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _deserialize(row):
    if not row:
        return None

    investigation = dict(row)

    for field in JSON_FIELDS:
        value = investigation.get(field)

        if value:
            investigation[field] = json.loads(
                value
            )
        elif field in {
            "email_analysis",
            "file_analysis",
            "challenge_result",
        }:
            investigation[field] = None
        else:
            investigation[field] = []

    investigation[
        "insufficient_evidence"
    ] = bool(
        investigation[
            "insufficient_evidence"
        ]
    )
    return investigation


def init_db():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                indicators TEXT NOT NULL,
                url_analysis TEXT NOT NULL,
                threat_intelligence TEXT NOT NULL,
                email_analysis TEXT,
                file_analysis TEXT,
                evidence_items TEXT,
                attack_findings TEXT,
                attack_chain TEXT,
                threat_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                reasoning TEXT NOT NULL,
                insufficient_evidence INTEGER NOT NULL,
                challenge_result TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(investigations)"
            )
        }

        for column in (
            "email_analysis",
            "file_analysis",
            "evidence_items",
            "attack_findings",
            "attack_chain",
        ):
            if column not in columns:
                connection.execute(
                    "ALTER TABLE investigations "
                    f"ADD COLUMN {column} TEXT"
                )


def save_investigation(
    content,
    indicators,
    url_analysis,
    threat_intelligence,
    ai_result,
    *,
    email_analysis=None,
    file_analysis=None,
    evidence_items=None,
    attack_findings=None,
    attack_chain=None,
):
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO investigations (
                content,
                indicators,
                url_analysis,
                threat_intelligence,
                email_analysis,
                file_analysis,
                evidence_items,
                attack_findings,
                attack_chain,
                threat_score,
                verdict,
                confidence,
                reasoning,
                insufficient_evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                content,
                json.dumps(indicators),
                json.dumps(url_analysis),
                json.dumps(
                    threat_intelligence
                ),
                (
                    json.dumps(email_analysis)
                    if email_analysis
                    is not None
                    else None
                ),
                (
                    json.dumps(file_analysis)
                    if file_analysis
                    is not None
                    else None
                ),
                json.dumps(
                    evidence_items or []
                ),
                json.dumps(
                    attack_findings or []
                ),
                json.dumps(
                    attack_chain or []
                ),
                ai_result[
                    "threat_score"
                ],
                ai_result["verdict"],
                ai_result["confidence"],
                ai_result["reasoning"],
                int(
                    ai_result[
                        "insufficient_evidence"
                    ]
                ),
            ),
        )
        return cursor.lastrowid


def save_challenge(
    investigation_id,
    challenge_result,
):
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE investigations
            SET challenge_result = ?
            WHERE id = ?
            """,
            (
                json.dumps(
                    challenge_result
                ),
                investigation_id,
            ),
        )


def get_investigation(
    investigation_id,
):
    with get_connection() as connection:
        row = connection.execute(
            (
                "SELECT * FROM "
                "investigations WHERE id = ?"
            ),
            (investigation_id,),
        ).fetchone()

    return _deserialize(row)


def get_investigations(limit=10):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM investigations
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        _deserialize(row)
        for row in rows
    ]

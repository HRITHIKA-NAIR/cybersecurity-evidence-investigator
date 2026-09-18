import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "investigations.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _deserialize(row):
    if not row:
        return None

    investigation = dict(row)
    investigation["indicators"] = json.loads(investigation["indicators"])
    investigation["url_analysis"] = json.loads(investigation["url_analysis"])
    investigation["threat_intelligence"] = json.loads(
        investigation["threat_intelligence"]
    )

    for field in ("email_analysis", "file_analysis"):
        if investigation.get(field):
            investigation[field] = json.loads(
                investigation[field]
            )
        else:
            investigation[field] = None

    if investigation["challenge_result"]:
        investigation["challenge_result"] = json.loads(
            investigation["challenge_result"]
        )

    investigation["insufficient_evidence"] = bool(
        investigation["insufficient_evidence"]
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
    email_analysis=None,
    file_analysis=None,
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
                threat_score,
                verdict,
                confidence,
                reasoning,
                insufficient_evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                content,
                json.dumps(indicators),
                json.dumps(url_analysis),
                json.dumps(threat_intelligence),
                (
                    json.dumps(email_analysis)
                    if email_analysis is not None
                    else None
                ),
                (
                    json.dumps(file_analysis)
                    if file_analysis is not None
                    else None
                ),
                ai_result["threat_score"],
                ai_result["verdict"],
                ai_result["confidence"],
                ai_result["reasoning"],
                int(ai_result["insufficient_evidence"]),
            ),
        )
        return cursor.lastrowid


def save_challenge(investigation_id, challenge_result):
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE investigations
            SET challenge_result = ?
            WHERE id = ?
            """,
            (
                json.dumps(challenge_result),
                investigation_id,
            ),
        )


def get_investigation(investigation_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM investigations WHERE id = ?",
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

    return [_deserialize(row) for row in rows]

from __future__ import annotations

import psycopg

from app.persistence.config import (
    DatabaseOperationError,
)
from app.persistence.pool import get_pool

# `users` intentionally has no Row Level Security policy: looking a user up
# by email during login happens *before* we know who the caller is, so
# there is no RLS context (app.current_user_id) to set yet. The API never
# exposes other users' rows (there is no "list users" or "get user by id
# other than yourself" endpoint), and password_hash is never serialized
# back to a client, so this table doesn't need row-level isolation the
# way investigation data does.


class EmailAlreadyRegisteredError(DatabaseOperationError):
    pass


def create_user(email: str, password_hash: str) -> dict:
    pool = get_pool()

    try:
        with pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    INSERT INTO users (email, password_hash)
                    VALUES (%s, %s)
                    RETURNING id, email, created_at
                    """,
                    (email, password_hash),
                ).fetchone()
        return row
    except psycopg.errors.UniqueViolation as exc:
        raise EmailAlreadyRegisteredError(
            "An account with this email already exists."
        ) from exc
    except Exception as exc:
        raise DatabaseOperationError(
            "Could not create user."
        ) from exc


def get_user_by_email(email: str) -> dict | None:
    pool = get_pool()

    try:
        with pool.connection() as connection:
            row = connection.execute(
                """
                SELECT id, email, password_hash, created_at
                FROM users
                WHERE email = %s
                """,
                (email,),
            ).fetchone()
        return row
    except Exception as exc:
        raise DatabaseOperationError(
            "Could not look up user."
        ) from exc


def get_user_by_id(user_id: int) -> dict | None:
    pool = get_pool()

    try:
        with pool.connection() as connection:
            row = connection.execute(
                """
                SELECT id, email, created_at
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            ).fetchone()
        return row
    except Exception as exc:
        raise DatabaseOperationError(
            "Could not look up user."
        ) from exc

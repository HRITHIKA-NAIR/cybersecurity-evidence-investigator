from __future__ import annotations

import os

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.persistence.config import (
    DatabaseOperationError,
    get_database_url,
)
from app.persistence.schema import (
    SCHEMA_STATEMENTS,
)

_POOL: ConnectionPool | None = None


def _pool_size(
    name: str,
    default: int,
) -> int:
    try:
        return max(
            1,
            int(
                os.getenv(
                    name,
                    str(default),
                )
            ),
        )
    except ValueError:
        return default


def get_pool() -> ConnectionPool:
    global _POOL

    if _POOL is None:
        min_size = _pool_size(
            "DB_POOL_MIN",
            1,
        )
        max_size = max(
            min_size,
            _pool_size(
                "DB_POOL_MAX",
                5,
            ),
        )

        _POOL = ConnectionPool(
            conninfo=get_database_url(),
            min_size=min_size,
            max_size=max_size,
            timeout=10,
            max_waiting=_pool_size(
                "DB_POOL_MAX_WAITING",
                20,
            ),
            reconnect_timeout=10,
            check=(
                ConnectionPool
                .check_connection
            ),
            open=False,
            kwargs={
                "row_factory": dict_row,
                "prepare_threshold": None,
            },
        )

        try:
            _POOL.open(
                wait=True,
                timeout=10,
            )
        except Exception as exc:
            _POOL = None
            raise DatabaseOperationError(
                "Could not connect to PostgreSQL."
            ) from exc

    return _POOL


def init_database() -> None:
    pool = get_pool()

    try:
        with pool.connection() as connection:
            with connection.transaction():
                for statement in SCHEMA_STATEMENTS:
                    connection.execute(
                        statement
                    )
    except Exception as exc:
        raise DatabaseOperationError(
            "Could not initialize PostgreSQL schema."
        ) from exc


def database_health() -> bool:
    try:
        pool = get_pool()

        with pool.connection(
            timeout=5
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    to_regclass(
                        'public.investigations'
                    ) AS table_name
                """
            ).fetchone()

        if (
            row
            and row.get("table_name")
        ):
            return True

        init_database()

        with pool.connection(
            timeout=5
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    to_regclass(
                        'public.investigations'
                    ) AS table_name
                """
            ).fetchone()

        return bool(
            row
            and row.get("table_name")
        )
    except Exception:
        return False


def close_database() -> None:
    global _POOL

    if _POOL is not None:
        _POOL.close()
        _POOL = None

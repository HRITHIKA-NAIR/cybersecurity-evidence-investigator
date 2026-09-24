from __future__ import annotations

import os
from threading import RLock

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
_POOL_LOCK = RLock()


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
    # Startup readiness and requests can arrive together on a cold service.
    with _POOL_LOCK:
        return _get_pool_locked()


def _get_pool_locked() -> ConnectionPool:
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
            _POOL.close()
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
    """Readiness requires the schema, RLS policies and usable restricted roles."""
    from app.persistence.schema import PRIVATE_TABLES
    try:
        with get_pool().connection(timeout=5) as connection:
            with connection.transaction():
                if os.getenv("APP_ENV") == "production":
                    login = connection.execute("""
                        SELECT r.rolsuper, r.rolbypassrls, r.rolinherit,
                          EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                  WHERE n.nspname = 'public' AND c.relname = ANY(%s)
                                  AND c.relowner = r.oid) AS owns_tables
                        FROM pg_roles r WHERE r.rolname = session_user
                    """, (list(PRIVATE_TABLES),)).fetchone()
                    if not login or any(login[key] for key in ("rolsuper", "rolbypassrls", "rolinherit", "owns_tables")):
                        return False
                row = connection.execute("""
                    SELECT count(*) AS ready
                    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = ANY(%s)
                    AND c.relrowsecurity
                    AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid
                                AND p.polname = 'evidence_owner_access')
                """, (list(PRIVATE_TABLES),)).fetchone()
                if not row or row["ready"] != len(PRIVATE_TABLES):
                    return False
                connection.execute("SET LOCAL ROLE evidence_app")
                role = connection.execute("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()
                if not role or role["rolbypassrls"] or role["rolsuper"]:
                    return False
                connection.execute("SELECT id FROM investigations LIMIT 0")
                connection.execute("SET LOCAL ROLE evidence_budget")
                connection.execute("SELECT bucket FROM usage_budgets LIMIT 0")
        return True
    except Exception:
        return False


def close_database() -> None:
    global _POOL

    with _POOL_LOCK:
        if _POOL is not None:
            _POOL.close()
            _POOL = None

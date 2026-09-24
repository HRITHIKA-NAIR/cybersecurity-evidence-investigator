"""Database access with transaction-local identity and a non-bypass RLS role."""
from contextlib import contextmanager
from uuid import UUID

from app.persistence.config import DatabaseOperationError
from app.persistence.pool import get_pool


@contextmanager
def user_connection(owner_id):
    if not owner_id:
        raise DatabaseOperationError("An authenticated owner is required.")
    owner = str(UUID(str(owner_id)))
    with get_pool().connection() as connection:
        with connection.transaction():
            connection.execute("SET LOCAL ROLE evidence_app")
            connection.execute("SELECT set_config('app.user_id', %s, true)", (owner,))
            yield connection


@contextmanager
def budget_connection():
    with get_pool().connection() as connection:
        with connection.transaction():
            connection.execute("SET LOCAL ROLE evidence_budget")
            yield connection

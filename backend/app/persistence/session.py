from __future__ import annotations


def set_rls_user(connection, user_id: int) -> None:
    """Bind this transaction to a user for Row Level Security.

    Every RLS policy on the investigations-owning tables checks
    ``current_setting('app.current_user_id', true)``. Setting it here with
    ``SET LOCAL`` scopes it to the *current transaction only* - it cannot
    leak to the next request that reuses this pooled connection, because
    Postgres discards ``SET LOCAL`` values at COMMIT/ROLLBACK regardless of
    connection pooling.

    Must be called as the first statement inside every
    ``connection.transaction()`` block that touches investigations or any
    table that references it, before any other query runs on that
    connection.
    """
    if user_id is None:
        raise ValueError(
            "set_rls_user requires a user_id; refusing to run a "
            "database query without an RLS context."
        )

    connection.execute(
        "SELECT set_config('app.current_user_id', %s, true)",
        (str(int(user_id)),),
    )

"""Provision the backend login using a migration-owner DATABASE_URL."""
import getpass
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from psycopg import sql
from app.persistence.pool import get_pool, close_database

password = getpass.getpass("New password for evidence_runtime (at least 24 characters): ")
if len(password) < 24:
    raise SystemExit("Password must have at least 24 characters.")
try:
    with get_pool().connection() as conn:
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'evidence_runtime'").fetchone():
            conn.execute("CREATE ROLE evidence_runtime LOGIN NOINHERIT NOBYPASSRLS")
        conn.execute(sql.SQL("ALTER ROLE evidence_runtime LOGIN NOINHERIT NOBYPASSRLS PASSWORD {}").format(sql.Literal(password)))
        conn.execute("GRANT evidence_app, evidence_budget TO evidence_runtime")
        database = conn.execute("SELECT current_database() AS name").fetchone()["name"]
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO evidence_runtime").format(sql.Identifier(database)))
    print("Runtime role configured. Use evidence_runtime in the backend URL; keep the owner URL for migrations only.")
finally:
    close_database()

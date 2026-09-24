"""Print safe setup diagnostics. Never print connection strings or raw DB errors."""
import argparse
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import psycopg
from app.persistence.config import get_database_url, DatabaseConfigurationError
from app.persistence.pool import database_health, close_database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readiness', action='store_true', help='Also verify tables, RLS and runtime roles. Use APP_ENV=production for the production role gate.')
    args = parser.parse_args()
    try:
        url = get_database_url()
        parsed = urlsplit(url)
        port = parsed.port or 5432
    except (DatabaseConfigurationError, ValueError):
        print('CONFIGURATION: missing or invalid DATABASE_URL. Copy the PostgreSQL session-pooler URI from Supabase Connect into backend/.env.')
        return 1
    try:
        socket.getaddrinfo(parsed.hostname, port)
    except (socket.gaierror, ValueError):
        print('DNS: database host cannot be resolved. Check the copied Connect URL.')
        return 1
    try:
        with psycopg.connect(url, connect_timeout=8) as conn:
            row = conn.execute("SELECT to_regclass('public.investigations')").fetchone()
            print('CONNECTION: successful (PostgreSQL answered).')
            print('SCHEMA:', 'present' if row[0] else 'missing; run python scripts/init_database.py with the migration owner')
            if not row[0]:
                return 2
    except psycopg.Error as exc:
        print('CONNECTION: failed; SQLSTATE:', exc.sqlstate or 'unavailable')
        print('Check project status, password, URI encoding, firewall and IPv4-compatible session pooler. Raw errors are suppressed to protect credentials.')
        return 1
    if args.readiness:
        try:
            ready = database_health()
            print('READINESS:', 'passed' if ready else 'failed; check all tables/policies and runtime role membership. Production requires a non-owner NOINHERIT NOBYPASSRLS login.')
            return 0 if ready else 3
        finally:
            close_database()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Delete application data after verified account closure; defaults to a dry run.
Run with a migration-owner DATABASE_URL, after removing the Auth identity and
pausing incoming analysis. This script never removes an Auth account itself.
"""
import argparse
import sys
from pathlib import Path
from uuid import UUID
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.persistence.pool import get_pool, close_database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('owner_id', type=UUID, help='UUID of the verified account owner')
    parser.add_argument('--execute', action='store_true', help='Apply deletion after an explicit confirmation')
    args = parser.parse_args()
    owner = str(args.owner_id)
    try:
        with get_pool().connection() as conn, conn.transaction():
            # On Supabase, require account removal first to prevent new authenticated work.
            if not conn.execute("SELECT to_regclass('auth.users') AS users").fetchone()['users']:
                raise SystemExit('Auth schema not found. Use the verified Supabase project; no data was changed.')
            if conn.execute('SELECT 1 FROM auth.users WHERE id = %s::uuid', (owner,)).fetchone():
                raise SystemExit('Auth identity still exists. Complete verified account closure first; no data was changed.')
            cases = conn.execute('SELECT count(*) AS count FROM investigations WHERE owner_id = %s::uuid', (owner,)).fetchone()['count']
            counters = conn.execute('SELECT count(*) AS count FROM usage_budgets WHERE bucket LIKE %s', (owner + ':%',)).fetchone()['count']
            print(f'Matching application data: {cases} cases and {counters} personal usage counters.')
            if not args.execute:
                print('DRY RUN: no changes. Pause incoming analysis and let in-flight requests finish before applying.')
                return
            if input('To permanently delete these records, type the account UUID: ').strip() != owner:
                raise SystemExit('Confirmation did not match; no data was changed.')
            conn.execute('DELETE FROM investigations WHERE owner_id = %s::uuid', (owner,))
            conn.execute('DELETE FROM usage_budgets WHERE bucket LIKE %s', (owner + ':%',))
        print('Application data deleted. Document separate provider/log/backup retention in the reply to the user.')
    finally:
        close_database()


if __name__ == '__main__':
    main()

"""Apply the idempotent schema using a migration-owner DATABASE_URL."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.persistence.pool import init_database, close_database
try:
    init_database()
    print("Database schema initialized.")
finally:
    close_database()

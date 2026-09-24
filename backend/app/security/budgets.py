"""Atomic persistent request budgets, shared across workers; fail closed."""
import os
from datetime import datetime, timezone
from fastapi import HTTPException
from app.persistence.access import budget_connection


def reserve_budget(owner_id: str) -> None:
    day = datetime.now(timezone.utc).date().isoformat()
    limits = (("global:" + day, int(os.getenv("DAILY_ANALYSIS_LIMIT", "50"))),
              (owner_id + ":" + day, int(os.getenv("USER_DAILY_ANALYSIS_LIMIT", "10"))))
    try:
        with budget_connection() as conn:
            with conn.transaction():
                for bucket, limit in limits:
                    row = conn.execute("""
                        INSERT INTO usage_budgets(bucket, used) SELECT %s, 1 WHERE %s > 0
                        ON CONFLICT (bucket) DO UPDATE SET used = usage_budgets.used + 1
                        WHERE usage_budgets.used < %s RETURNING used
                    """, (bucket, limit, limit)).fetchone()
                    if not row:
                        raise HTTPException(429, "Today's investigation limit has been reached. Try again tomorrow.", headers={"Retry-After": "3600"})
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Investigations are paused while the database is unavailable.") from None

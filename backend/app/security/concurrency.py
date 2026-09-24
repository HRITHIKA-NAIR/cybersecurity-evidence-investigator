"""Bound expensive in-flight requests within one free-tier API worker."""
import os
from threading import BoundedSemaphore
from fastapi import Depends, HTTPException
from app.security.auth import require_user

slots = BoundedSemaphore(max(1, int(os.getenv("MAX_INFLIGHT_ANALYSES", "2"))))

def analysis_slot(owner_id: str = Depends(require_user)):
    if not slots.acquire(blocking=False):
        raise HTTPException(503, "The investigation service is busy. Try again shortly.", headers={"Retry-After": "30"})
    try:
        yield owner_id
    finally:
        slots.release()

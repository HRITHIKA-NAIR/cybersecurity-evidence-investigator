"""Validate bearer tokens with the configured Supabase Auth service.
No browser-supplied user ID or decoded, unverified JWT is trusted.
"""
import logging
import os
from uuid import UUID
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)

async def require_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "Sign in to use private investigations.", headers={"WWW-Authenticate": "Bearer"})
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or not key:
        raise HTTPException(503, "Account service is not configured.")
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(url + "/auth/v1/user", headers={
                "apikey": key, "Authorization": "Bearer " + credentials.credentials,
            })
        if response.status_code in (401, 403):
            logger.info("security.auth_rejected")
            raise HTTPException(401, "Your session expired. Please sign in again.")
        response.raise_for_status()
        user = response.json()
        if not user.get("email_confirmed_at") or user.get("is_anonymous"):
            raise HTTPException(403, "Confirm your email before investigating.")
        return str(UUID(user["id"]))
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        raise HTTPException(503, "Account verification is temporarily unavailable.") from None

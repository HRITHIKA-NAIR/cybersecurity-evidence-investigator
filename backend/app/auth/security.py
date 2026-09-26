from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(days=7)


class AuthConfigurationError(RuntimeError):
    pass


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret or len(secret) < 32:
        # Deliberately not falling back to a generated/default secret:
        # a silently-generated secret that changes on every restart gives
        # a false sense of security and makes the failure mode (tokens
        # from before a restart look "valid" against a *different* app
        # instance in a multi-worker deploy) confusing to debug. Fail
        # loudly and make the operator set it instead.
        raise AuthConfigurationError(
            "JWT_SECRET is not configured (or is too short - use at "
            "least 32 random characters). Generate one with, e.g., "
            "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"` "
            "and set it as a backend-only environment variable."
        )
    return secret


def hash_password(password: str) -> str:
    # bcrypt only uses the first 72 bytes of the input; anything past
    # that is silently ignored by the algorithm itself, so we reject
    # long passwords explicitly instead of pretending the rest matters.
    if len(password.encode("utf-8")) > 72:
        raise ValueError(
            "Password must be 72 bytes or fewer."
        )
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(
        password.encode("utf-8"), salt
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except ValueError:
        # Malformed hash in storage - never treat as a match.
        return False


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
    }
    return jwt.encode(
        payload, _jwt_secret(), algorithm=JWT_ALGORITHM
    )


class InvalidTokenError(Exception):
    pass


def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(
            token,
            _jwt_secret(),
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    try:
        return int(payload["sub"])
    except (KeyError, ValueError, TypeError) as exc:
        raise InvalidTokenError(
            "Token subject is missing or malformed."
        ) from exc

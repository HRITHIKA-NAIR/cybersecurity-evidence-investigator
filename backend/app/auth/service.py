from __future__ import annotations

import re

from app.auth.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.persistence.users import (
    EmailAlreadyRegisteredError,
    create_user,
    get_user_by_email,
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class InvalidCredentialsError(Exception):
    pass


class WeakPasswordError(Exception):
    pass


class InvalidEmailError(Exception):
    pass


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def register(email: str, password: str) -> dict:
    email = _normalize_email(email)

    if not _EMAIL_RE.match(email):
        raise InvalidEmailError("Enter a valid email address.")

    if len(password) < 8:
        raise WeakPasswordError(
            "Password must be at least 8 characters."
        )
    if len(password.encode("utf-8")) > 72:
        raise WeakPasswordError(
            "Password must be 72 bytes or fewer."
        )

    password_hash = hash_password(password)

    try:
        user = create_user(email, password_hash)
    except EmailAlreadyRegisteredError:
        # Same message as a real "wrong password" would get in login()
        # below is *not* used here on purpose: registration legitimately
        # needs to tell a user "that email is taken" so they can try
        # logging in instead. That's a normal, low-sensitivity signal for
        # sign-up flows (unlike login, where saying "no such user" vs.
        # "wrong password" would leak which emails have accounts).
        raise

    token = create_access_token(user["id"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
        },
    }


def login(email: str, password: str) -> dict:
    email = _normalize_email(email)
    user = get_user_by_email(email)

    if user is None or not verify_password(
        password, user["password_hash"]
    ):
        # Deliberately identical error for "no such user" and "wrong
        # password" - distinguishing them lets an attacker enumerate
        # which emails have accounts.
        raise InvalidCredentialsError(
            "Incorrect email or password."
        )

    token = create_access_token(user["id"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
        },
    }

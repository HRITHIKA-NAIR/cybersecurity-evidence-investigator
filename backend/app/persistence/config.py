from __future__ import annotations

import os
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

from dotenv import load_dotenv

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / "backend" / ".env")
load_dotenv(ROOT / ".env")


class DatabaseOperationError(RuntimeError):
    pass


class DatabaseConfigurationError(
    DatabaseOperationError
):
    pass


def normalize_database_url(
    value: str | None,
) -> str:
    raw = (value or "").strip()

    if not raw:
        raise DatabaseConfigurationError(
            "DATABASE_URL is not configured."
        )

    parsed = urlsplit(raw)

    if parsed.scheme not in {
        "postgres",
        "postgresql",
    }:
        raise DatabaseConfigurationError(
            "DATABASE_URL must use PostgreSQL."
        )

    if not parsed.hostname:
        raise DatabaseConfigurationError(
            "DATABASE_URL does not contain a host."
        )

    query = dict(
        parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
    )

    is_local = parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }

    if not is_local:
        sslmode = query.get(
            "sslmode",
            "",
        ).lower()

        if sslmode in {
            "",
            "disable",
            "allow",
            "prefer",
        }:
            query["sslmode"] = "require"

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            parsed.fragment,
        )
    )


def get_database_url() -> str:
    return normalize_database_url(
        os.getenv("DATABASE_URL")
    )

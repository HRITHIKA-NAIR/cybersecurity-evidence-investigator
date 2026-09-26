import pytest

from app.persistence.config import (
    DatabaseConfigurationError,
    normalize_database_url,
)
from app.persistence.schema import (
    SCHEMA_STATEMENTS,
)


def test_remote_database_url_requires_ssl():
    url = normalize_database_url(
        "postgresql://user:pass@db.example.com:5432/postgres"
    )

    assert "sslmode=require" in url


def test_local_database_url_can_remain_local():
    url = normalize_database_url(
        "postgresql://user:pass@localhost:5432/evidence"
    )

    assert "sslmode=" not in url


def test_rejects_non_postgresql_database_url():
    with pytest.raises(
        DatabaseConfigurationError
    ):
        normalize_database_url(
            "sqlite:///investigations.db"
        )


def test_schema_contains_v2_relational_tables():
    schema = "\n".join(
        SCHEMA_STATEMENTS
    ).lower()

    for table in (
        "investigations",
        "artifacts",
        "evidence_items",
        "attack_findings",
        "finding_evidence",
        "attack_chain_stages",
        "email_metadata",
        "redirect_hops",
        "challenge_results",
    ):
        assert (
            "create table if not exists "
            + table
        ) in schema

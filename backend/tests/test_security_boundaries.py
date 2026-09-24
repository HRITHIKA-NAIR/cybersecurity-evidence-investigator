from contextlib import contextmanager
from uuid import uuid4
import httpx
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from app.main import app
from app.security import auth, budgets
from app.security.rate_limit import RateLimiter
from app.persistence.access import user_connection
from app.persistence.config import DatabaseOperationError

def test_private_routes_require_authentication():
    client = TestClient(app)
    for method, path, kwargs in [
        ("GET", "/investigations", {}),
        ("GET", "/investigations/1", {}),
        ("DELETE", "/investigations/1", {}),
        ("POST", "/investigate", {"json": {"content": "synthetic test"}}),
        ("POST", "/challenge", {"json": {"investigation_id": 1}}),
        ("POST", "/investigate-file", {"files": {"file": ("sample.txt", b"test", "text/plain")}}),
    ]:
        assert client.request(method, path, **kwargs).status_code == 401

def test_body_is_bounded_before_parser_and_routes():
    client = TestClient(app)
    assert client.post("/investigate", content=b"x" * (512 * 1024 + 1)).status_code == 413
    assert client.post("/investigate-file", headers={"Content-Length": str(12 * 1024 * 1024)}).status_code == 413


def test_early_security_rejections_have_no_store_headers():
    response = TestClient(app).post("/investigate", content=b"x" * (512 * 1024 + 1))
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"

def test_api_headers_and_exact_cors():
    client = TestClient(app)
    response = client.get("/live", headers={"Origin": "http://localhost:5173"})
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in client.get("/live", headers={"Origin": "https://evil.example"}).headers

def test_missing_owner_fails_closed_before_database_access():
    with pytest.raises(DatabaseOperationError):
        with user_connection(None):
            pytest.fail("Must not obtain a connection")

def test_rate_limit_and_window_expiration():
    clock = [0.0]
    limiter = RateLimiter(limit=2, window=60, clock=lambda: clock[0])
    assert limiter.allow("peer")
    assert limiter.allow("peer")
    assert not limiter.allow("peer")
    assert limiter.allow("other")
    clock[0] = 61
    assert limiter.allow("peer")

def test_budget_database_failure_does_not_allow_paid_work(monkeypatch):
    @contextmanager
    def unavailable():
        raise RuntimeError("synthetic DB outage")
        yield
    monkeypatch.setattr(budgets, "budget_connection", unavailable)
    with pytest.raises(HTTPException) as error:
        budgets.reserve_budget(str(uuid4()))
    assert error.value.status_code == 503

@pytest.mark.parametrize("status,payload,expected", [
    (401, {}, 401),
    (200, {"id": str(uuid4()), "email_confirmed_at": None}, 403),
    (200, {"id": str(uuid4()), "email_confirmed_at": "today", "is_anonymous": True}, 403),
    (200, {"id": "not-a-uuid", "email_confirmed_at": "today"}, 503),
    (500, {}, 503),
])
def test_supabase_rejection_is_fail_closed(monkeypatch, status, payload, expected):
    import asyncio
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", "synthetic-public-key")
    class Client:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, *args, **kwargs):
            return httpx.Response(status, json=payload, request=httpx.Request("GET", args[0]))
    monkeypatch.setattr(auth.httpx, "AsyncClient", Client)
    with pytest.raises(HTTPException) as error:
        asyncio.run(auth.require_user(HTTPAuthorizationCredentials(scheme="Bearer", credentials="synthetic-token")))
    assert error.value.status_code == expected

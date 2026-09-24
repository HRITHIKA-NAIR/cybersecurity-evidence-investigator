"""Bound requests before multipart parsing; never log submitted evidence."""
import logging
import os
from starlette.responses import JSONResponse
from app.security.rate_limit import RateLimiter

log = logging.getLogger(__name__)
MAX_BODY = 11 * 1024 * 1024  # 10 MiB upload plus multipart overhead

class SecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self.limiter = RateLimiter()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        async def secure_send(message):
            if message["type"] == "http.response.start":
                h = list(message.get("headers", []))
                h += [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
                      (b"x-frame-options", b"DENY"), (b"cache-control", b"no-store")]
                if os.getenv("APP_ENV") == "production":
                    h.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = h
                if message["status"] >= 400:
                    log.info("security.http_error status=%s method=%s", message["status"], scope["method"])
            await send(message)
        headers = dict(scope.get("headers", []))
        peer = scope.get("client") or ("unknown", 0)
        if not self.limiter.allow(peer[0]):
            return await JSONResponse({"detail": "Too many requests. Wait a minute and try again."}, 429, headers={"Retry-After": "60"})(scope, receive, secure_send)
        limit = MAX_BODY if scope["path"] == "/investigate-file" else 512 * 1024
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid request length."}, 400)(scope, receive, secure_send)
        if declared < 0 or declared > limit:
            return await JSONResponse({"detail": "Request exceeds the size limit."}, 413)(scope, receive, secure_send)
        # Consume only a bounded body, so chunked bodies cannot bypass the limit.
        body = bytearray()
        if scope["method"] in ("POST", "PUT", "PATCH"):
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > limit:
                    log.info("security.request_too_large")
                    return await JSONResponse({"detail": "Request exceeds the size limit."}, 413)(scope, receive, secure_send)
                if not message.get("more_body", False):
                    break
        body_sent = False
        async def replay():
            nonlocal body_sent
            if not body_sent and scope["method"] in ("POST", "PUT", "PATCH"):
                body_sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        await self.app(scope, replay, secure_send)

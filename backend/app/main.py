import logging
import os
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import (
    CORSMiddleware,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.concurrency import (
    run_in_threadpool,
)

from app.database import (
    DatabaseOperationError,
    close_database,
    database_health,
    get_investigation,
    get_investigations,
    init_database,
)
from app.parsers.file_reader import (
    FileReaderError,
    MAX_UPLOAD_BYTES,
    read_uploaded_file,
)
from app.services.challenge_service import (
    run_challenge,
)
from app.services.investigation_service import (
    run_investigation,
)

LOGGER = logging.getLogger(__name__)
MAX_TEXT_CHARS = 100_000


@asynccontextmanager
async def lifespan(_app):
    try:
        init_database()
    except Exception as exc:
        LOGGER.error(
            "Database initialization failed: %s",
            type(exc).__name__,
        )

    yield
    close_database()


app = FastAPI(
    title=(
        "Cybersecurity Evidence "
        "Investigator"
    ),
    lifespan=lifespan,
)

frontend_origin = os.getenv(
    "FRONTEND_ORIGIN"
)
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

if frontend_origin:
    allowed_origins.append(
        frontend_origin.rstrip("/")
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _client_key(request: Request) -> str:
    """Rate-limit key derived from the caller's IP.

    Render (and most PaaS hosts) sit the app behind a reverse proxy, so
    ``request.client.host`` is the proxy's address, not the caller's. Render
    sets ``X-Forwarded-For`` to "<client>, <proxy hops...>" - the first
    entry is the original client.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(
    key_func=_client_key,
    default_limits=["60/minute"],
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
def _rate_limit_handler(
    _request: Request,
    exc: RateLimitExceeded,
):
    response = JSONResponse(
        status_code=429,
        content={
            "detail": (
                "Too many requests. Please wait "
                "before trying again."
            )
        },
    )
    response.headers["Retry-After"] = "60"
    return response


class InvestigationRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=MAX_TEXT_CHARS,
    )


class ChallengeRequest(BaseModel):
    investigation_id: int


@app.get("/")
def root():
    return {
        "message": (
            "Cybersecurity Evidence "
            "Investigator API is running"
        )
    }


@app.get("/health")
def health():
    if not database_health():
        raise HTTPException(
            status_code=503,
            detail=(
                "Service is running, but "
                "PostgreSQL is unavailable."
            ),
        )

    return {
        "status": "ok",
        "database": "ok",
    }


@app.post("/investigate")
@limiter.limit("5/minute;60/day")
def investigate(
    request: Request,
    payload: InvestigationRequest,
):
    return run_investigation(
        payload.content
    )


@app.post("/investigate-file")
@limiter.limit("5/minute;60/day")
async def investigate_file(
    request: Request,
    file: UploadFile = File(...),
):
    data = await file.read(
        MAX_UPLOAD_BYTES + 1
    )
    await file.close()

    try:
        parsed = await run_in_threadpool(
            read_uploaded_file,
            file.filename or "upload",
            file.content_type,
            data,
        )
    except FileReaderError as exc:
        raise HTTPException(
            status_code=(
                exc.status_code
            ),
            detail=str(exc),
        ) from exc

    return await run_in_threadpool(
        run_investigation,
        parsed["content"],
        parsed["file_info"],
        parsed.get(
            "email_analysis"
        ),
        parsed.get(
            "file_analysis"
        ),
    )


@app.post("/challenge")
@limiter.limit("10/minute;100/day")
def challenge(
    request: Request,
    payload: ChallengeRequest,
):
    try:
        result = run_challenge(
            payload.investigation_id
        )
    except DatabaseOperationError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Challenge is temporarily "
                "unavailable because persistent "
                "history cannot be reached."
            ),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Investigation not found."
            ),
        )

    return result


@app.get("/investigations")
@limiter.limit("30/minute")
def investigations(
    request: Request,
):
    try:
        return get_investigations(
            limit=10
        )
    except DatabaseOperationError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Investigation history is "
                "temporarily unavailable."
            ),
        ) from exc


@app.get("/investigations/{investigation_id}")
@limiter.limit("30/minute")
def investigation_detail(
    investigation_id: int,
    request: Request,
):
    try:
        result = get_investigation(
            investigation_id
        )
    except DatabaseOperationError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Investigation history is "
                "temporarily unavailable."
            ),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    return result

import logging
import os
from contextlib import asynccontextmanager

from fastapi import (
    Depends,
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

from app.auth.dependencies import (
    CurrentUser,
    get_current_user,
)
from app.auth.security import AuthConfigurationError
from app.auth.service import (
    InvalidCredentialsError,
    InvalidEmailError,
    WeakPasswordError,
    login as auth_login,
    register as auth_register,
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
from app.persistence.users import (
    EmailAlreadyRegisteredError,
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


class RegisterRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(
        min_length=8, max_length=72
    )


class LoginRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(
        min_length=1, max_length=72
    )


def _auth_config_response():
    raise HTTPException(
        status_code=503,
        detail=(
            "Authentication is not configured on the "
            "server (missing JWT_SECRET)."
        ),
    )


@app.post("/auth/register")
@limiter.limit("5/minute;20/day")
def register_route(
    request: Request,
    payload: RegisterRequest,
):
    try:
        return auth_register(
            payload.email, payload.password
        )
    except (
        InvalidEmailError,
        WeakPasswordError,
    ) as exc:
        raise HTTPException(
            status_code=422, detail=str(exc)
        ) from exc
    except EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=409, detail=str(exc)
        ) from exc
    except AuthConfigurationError:
        _auth_config_response()
    except DatabaseOperationError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not create account right now.",
        ) from exc


@app.post("/auth/login")
@limiter.limit("10/minute;50/day")
def login_route(
    request: Request,
    payload: LoginRequest,
):
    try:
        return auth_login(
            payload.email, payload.password
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=401, detail=str(exc)
        ) from exc
    except AuthConfigurationError:
        _auth_config_response()
    except DatabaseOperationError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not sign in right now.",
        ) from exc


@app.get("/auth/me")
def me_route(
    current_user: CurrentUser = Depends(
        get_current_user
    ),
):
    return {"id": current_user.id}


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
    current_user: CurrentUser = Depends(
        get_current_user
    ),
):
    return run_investigation(
        payload.content,
        user_id=current_user.id,
    )


@app.post("/investigate-file")
@limiter.limit("5/minute;60/day")
async def investigate_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: CurrentUser = Depends(
        get_current_user
    ),
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
        user_id=current_user.id,
    )


@app.post("/challenge")
@limiter.limit("10/minute;100/day")
def challenge(
    request: Request,
    payload: ChallengeRequest,
    current_user: CurrentUser = Depends(
        get_current_user
    ),
):
    try:
        result = run_challenge(
            payload.investigation_id,
            user_id=current_user.id,
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
    current_user: CurrentUser = Depends(
        get_current_user
    ),
):
    try:
        return get_investigations(
            user_id=current_user.id,
            limit=10,
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
    current_user: CurrentUser = Depends(
        get_current_user
    ),
):
    try:
        result = get_investigation(
            investigation_id,
            user_id=current_user.id,
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

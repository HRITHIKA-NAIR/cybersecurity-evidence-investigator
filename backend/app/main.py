import logging
import os
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    Depends,
    File,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import (
    CORSMiddleware,
)
from pydantic import BaseModel, Field, field_validator
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

from app.security.auth import require_user
from app.security.http import SecurityMiddleware
from app.security.budgets import reserve_budget
from app.security.concurrency import analysis_slot
from app.persistence.reader import get_investigation_summaries

LOGGER = logging.getLogger(__name__)
MAX_TEXT_CHARS = 100_000


@asynccontextmanager
async def lifespan(_app):
    try:
        if os.getenv("APP_ENV") != "production":
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
    docs_url=None if os.getenv("APP_ENV") == "production" else "/docs",
    redoc_url=None if os.getenv("APP_ENV") == "production" else "/redoc",
    openapi_url=None if os.getenv("APP_ENV") == "production" else "/openapi.json",
)

frontend_origin = os.getenv(
    "FRONTEND_ORIGIN"
)
allowed_origins = [] if os.getenv("APP_ENV") == "production" else [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

if frontend_origin:
    allowed_origins.append(
        frontend_origin.rstrip("/")
    )

app.add_middleware(SecurityMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


class InvestigationRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=MAX_TEXT_CHARS,
    )

    @field_validator("content")
    @classmethod
    def meaningful_content(cls, value):
        if not value.strip():
            raise ValueError("Enter content to investigate.")
        return value


class ChallengeRequest(BaseModel):
    investigation_id: int = Field(gt=0)


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
def investigate(
    request: InvestigationRequest,
    owner_id: str = Depends(analysis_slot),
):
    reserve_budget(owner_id)
    return run_investigation(
        request.content, owner_id=owner_id
    )


@app.post("/investigate-file")
async def investigate_file(
    file: UploadFile = File(...),
    owner_id: str = Depends(analysis_slot),
):
    await run_in_threadpool(reserve_budget, owner_id)
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
        owner_id=owner_id,
    )


@app.post("/challenge")
def challenge(
    request: ChallengeRequest,
    owner_id: str = Depends(analysis_slot),
):
    reserve_budget(owner_id)
    try:
        result = run_challenge(
            request.investigation_id, owner_id=owner_id
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
def investigations(summary: bool = False, owner_id: str = Depends(require_user)):
    try:
        if summary:
            return get_investigation_summaries(owner_id=owner_id)
        return get_investigations(
            limit=100, owner_id=owner_id
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
def investigation_detail(
    investigation_id: int,
    owner_id: str = Depends(require_user),
):
    try:
        result = get_investigation(
            investigation_id, owner_id=owner_id
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


@app.get("/live")
def live():
    return {"status": "running"}


@app.delete("/investigations/{investigation_id}")
def delete_investigation(investigation_id: int, owner_id: str = Depends(require_user)):
    from app.persistence.access import user_connection
    try:
        with user_connection(owner_id) as conn:
            row = conn.execute("DELETE FROM investigations WHERE id = %s AND owner_id = %s::uuid RETURNING id", (investigation_id, owner_id)).fetchone()
        if not row:
            raise HTTPException(404, "Investigation not found.")
        return {"status": "deleted"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "History is temporarily unavailable.") from None

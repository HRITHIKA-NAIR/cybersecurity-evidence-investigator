import logging
import os
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import (
    CORSMiddleware,
)
from pydantic import BaseModel, Field
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
def investigate(
    request: InvestigationRequest,
):
    return run_investigation(
        request.content
    )


@app.post("/investigate-file")
async def investigate_file(
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
def challenge(
    request: ChallengeRequest,
):
    try:
        result = run_challenge(
            request.investigation_id
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
def investigations():
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
def investigation_detail(
    investigation_id: int,
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

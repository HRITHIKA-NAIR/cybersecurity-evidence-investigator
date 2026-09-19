import os

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import (
    CORSMiddleware,
)
from pydantic import BaseModel
from starlette.concurrency import (
    run_in_threadpool,
)

from app.database import (
    get_investigations,
    init_db,
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

app = FastAPI(
    title=(
        "Cybersecurity Evidence "
        "Investigator"
    )
)
init_db()

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
    content: str


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
    return {"status": "ok"}


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
    result = run_challenge(
        request.investigation_id
    )

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
    return get_investigations(
        limit=10
    )

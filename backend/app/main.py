from fastapi import FastAPI
from app.tools.indicators import extract_indicators
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Cybersecurity Evidence Investigator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigationRequest(BaseModel):
    content: str


@app.get("/")
def root():
    return {"message": "Cybersecurity Evidence Investigator API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/investigate")
def investigate(request: InvestigationRequest):
    indicators = extract_indicators(request.content)

    return {
        "status": "completed",
        "indicators": indicators,
        "threat_score": 0,
        "verdict": "Evidence collection pending",
        "confidence": 0,
        "evidence": [
            f"Extracted {len(indicators['urls'])} URL(s)",
            f"Extracted {len(indicators['domains'])} domain(s)",
            f"Extracted {len(indicators['emails'])} email address(es)",
        ],
    }
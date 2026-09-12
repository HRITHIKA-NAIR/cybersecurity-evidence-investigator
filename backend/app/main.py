from fastapi import FastAPI
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
    return {
        "status": "completed",
        "threat_score": 50,
        "verdict": "Analysis pending",
        "confidence": 0,
        "evidence": [
            "Input received successfully",
            "Frontend connected to backend"
        ]
    }
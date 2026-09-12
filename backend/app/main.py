from fastapi import FastAPI
from app.tools.indicators import extract_indicators
from fastapi.middleware.cors import CORSMiddleware
from app.tools.url_analysis import analyze_url
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

    url_results = [
        analyze_url(url)
        for url in indicators["urls"]
    ]

    evidence = [
        f"Extracted {len(indicators['urls'])} URL(s)",
        f"Extracted {len(indicators['domains'])} domain(s)",
        f"Extracted {len(indicators['emails'])} email address(es)",
    ]

    for result in url_results:
        for finding in result["findings"]:
            evidence.append(finding["message"])

    return {
        "status": "completed",
        "indicators": indicators,
        "url_analysis": url_results,
        "threat_score": 0,
        "verdict": "External evidence collection pending",
        "confidence": 0,
        "evidence": evidence,
    }
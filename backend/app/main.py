from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.tools.indicators import extract_indicators
from app.tools.url_analysis import analyze_url
from app.tools.virustotal import check_domain
from app.tools.ai_analysis import analyze_evidence
from app.tools.ai_analysis import (analyze_evidence,challenge_assessment,)
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

class ChallengeRequest(BaseModel):
    content: str
    indicators: dict
    url_analysis: list
    threat_intelligence: list
    original_assessment: dict


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

    domain_results = [
        check_domain(domain)
        for domain in indicators["domains"]
    ]

    evidence = [
        f"Extracted {len(indicators['urls'])} URL(s)",
        f"Extracted {len(indicators['domains'])} domain(s)",
        f"Extracted {len(indicators['emails'])} email address(es)",
    ]

    for result in url_results:
        for finding in result["findings"]:
            evidence.append(finding["message"])

    for result in domain_results:
        if result["status"] == "success":
            evidence.append(
                f"VirusTotal: {result['malicious']} malicious, "
                f"{result['suspicious']} suspicious detections for "
                f"{result['domain']}"
            )
        else:
            evidence.append(
                f"VirusTotal: "
                f"{result.get('message', 'No result')} "
                f"for {result['domain']}"
            )

    ai_result = analyze_evidence(
        request.content,
        indicators,
        url_results,
        domain_results,
    )

    return {
        "status": "completed",
        "indicators": indicators,
        "url_analysis": url_results,
        "threat_intelligence": domain_results,
        "threat_score": ai_result["threat_score"],
        "verdict": ai_result["verdict"],
        "confidence": ai_result["confidence"],
        "reasoning": ai_result["reasoning"],
        "insufficient_evidence": ai_result[
            "insufficient_evidence"
        ],
        "evidence": evidence,
        "stages": {
            "extract_indicators": True,
            "analyze_url": True,
            "investigate_domain": True,
            "gather_evidence": True,
            "counter_evidence": False,
            "calculate_assessment":
                ai_result["status"] == "success",
        },
    }

@app.post("/challenge")
def challenge(request: ChallengeRequest):
    result = challenge_assessment(
        request.content,
        request.indicators,
        request.url_analysis,
        request.threat_intelligence,
        request.original_assessment,
    )

    return result
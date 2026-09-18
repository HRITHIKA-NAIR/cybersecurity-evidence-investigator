import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from app.database import (
    get_investigation,
    get_investigations,
    init_db,
    save_challenge,
    save_investigation,
)
from app.parsers.file_reader import (
    FileReaderError,
    MAX_UPLOAD_BYTES,
    read_uploaded_file,
)
from app.tools.ai_analysis import analyze_evidence, challenge_assessment
from app.tools.indicators import extract_indicators
from app.tools.url_analysis import analyze_url
from app.tools.virustotal import check_domain, check_ip

app = FastAPI(title="Cybersecurity Evidence Investigator")
init_db()

frontend_origin = os.getenv("FRONTEND_ORIGIN")
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

if frontend_origin:
    allowed_origins.append(frontend_origin.rstrip("/"))

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


def _run_investigation(
    content: str,
    file_info: dict | None = None,
    email_analysis: dict | None = None,
    file_analysis: dict | None = None,
):
    indicators = extract_indicators(content)

    if file_analysis and file_analysis.get("urls"):
        static_indicators = extract_indicators(
            "\n".join(file_analysis["urls"])
        )

        for key in ("urls", "domains", "emails"):
            for item in static_indicators[key]:
                if item not in indicators[key]:
                    indicators[key].append(item)

    url_results = [
        analyze_url(url)
        for url in indicators["urls"]
    ]

    domain_results = [
        check_domain(domain)
        for domain in indicators["domains"]
    ]

    if email_analysis:
        email_analysis = dict(email_analysis)
        originating_ip = email_analysis.get(
            "originating_ip"
        )

        if originating_ip:
            email_analysis[
                "routing_intelligence"
            ] = check_ip(originating_ip)

    evidence = [
        f"Extracted {len(indicators['urls'])} URL(s)",
        f"Extracted {len(indicators['domains'])} domain(s)",
        f"Extracted {len(indicators['emails'])} email address(es)",
    ]

    if file_info:
        evidence.insert(
            0,
            (
                f"File: {file_info['filename']} "
                f"({file_info['extension']}, "
                f"{file_info['size_bytes']} bytes)"
            ),
        )
        evidence.append(
            f"SHA-256: {file_info['sha256']}"
        )
        if file_info["truncated"]:
            evidence.append(
                "Extracted text was truncated for safe processing."
            )

    if file_analysis:
        for finding in file_analysis.get(
            "findings",
            [],
        ):
            detail = (
                finding.get("evidence")
                or [finding["attack_type"]]
            )[0]
            evidence.append(
                "Static file finding: "
                f"{finding['attack_type']} — {detail}"
            )

    for result in url_results:
        for finding in result["findings"]:
            evidence.append(finding["message"])

    if email_analysis:
        claimed_sender = email_analysis.get(
            "sender_address"
        )
        if claimed_sender:
            evidence.append(
                f"Claimed sender address: {claimed_sender}"
            )

        originating_ip = email_analysis.get(
            "originating_ip"
        )
        if originating_ip:
            evidence.append(
                f"Earliest usable public routing IP: {originating_ip}"
            )

        routing = email_analysis.get(
            "routing_intelligence",
            {},
        )
        if routing.get("status") == "success":
            if routing.get("country"):
                evidence.append(
                    "Likely routing country: "
                    f"{routing['country']}"
                )
            if routing.get("as_owner"):
                evidence.append(
                    "Routing network owner: "
                    f"{routing['as_owner']}"
                )

        authentication = email_analysis.get(
            "authentication",
            {},
        )
        for mechanism in (
            "spf",
            "dkim",
            "dmarc",
        ):
            status = authentication.get(
                mechanism
            )
            if (
                status
                and status != "not_reported"
            ):
                evidence.append(
                    "Header-reported "
                    f"{mechanism.upper()}: "
                    f"{status}"
                )

        for warning in email_analysis.get(
            "warnings",
            [],
        ):
            evidence.append(
                f"Email header indicator: {warning}"
            )

    for result in domain_results:
        if result["status"] == "success":
            evidence.append(
                f"VirusTotal: {result['malicious']} malicious, "
                f"{result['suspicious']} suspicious detections for "
                f"{result['domain']}"
            )
        else:
            evidence.append(
                "VirusTotal: "
                f"{result.get('message', 'No result')} "
                f"for {result['domain']}"
            )

    ai_result = analyze_evidence(
        content,
        indicators,
        url_results,
        domain_results,
        email_analysis,
        file_analysis,
    )

    investigation_id = save_investigation(
        content,
        indicators,
        url_results,
        domain_results,
        ai_result,
        email_analysis=email_analysis,
        file_analysis=file_analysis,
    )

    return {
        "status": "completed",
        "investigation_id": investigation_id,
        "file_info": file_info,
        "email_analysis": email_analysis,
        "file_analysis": file_analysis,
        "indicators": indicators,
        "url_analysis": url_results,
        "threat_intelligence": domain_results,
        "threat_score": ai_result["threat_score"],
        "verdict": ai_result["verdict"],
        "confidence": ai_result["confidence"],
        "reasoning": ai_result["reasoning"],
        "insufficient_evidence": ai_result["insufficient_evidence"],
        "evidence": evidence,
        "stages": {
            "extract_indicators": True,
            "analyze_url": True,
            "investigate_domain": True,
            "gather_evidence": True,
            "counter_evidence": False,
            "calculate_assessment": ai_result["status"] == "success",
        },
    }


@app.get("/")
def root():
    return {"message": "Cybersecurity Evidence Investigator API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/investigate")
def investigate(request: InvestigationRequest):
    return _run_investigation(request.content)


@app.post("/investigate-file")
async def investigate_file(file: UploadFile = File(...)):
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()

    try:
        parsed = read_uploaded_file(
            file.filename or "upload",
            file.content_type,
            data,
        )
    except FileReaderError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=str(exc),
        ) from exc

    return await run_in_threadpool(
        _run_investigation,
        parsed["content"],
        parsed["file_info"],
        parsed.get("email_analysis"),
        parsed.get("file_analysis"),
    )


@app.post("/challenge")
def challenge(request: ChallengeRequest):
    investigation = get_investigation(request.investigation_id)

    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    original_assessment = {
        "threat_score": investigation["threat_score"],
        "verdict": investigation["verdict"],
        "confidence": investigation["confidence"],
        "reasoning": investigation["reasoning"],
    }

    result = challenge_assessment(
        investigation["content"],
        investigation["indicators"],
        investigation["url_analysis"],
        investigation["threat_intelligence"],
        original_assessment,
        investigation.get("email_analysis"),
        investigation.get("file_analysis"),
    )

    save_challenge(request.investigation_id, result)
    return result


@app.get("/investigations")
def investigations():
    return get_investigations(limit=10)

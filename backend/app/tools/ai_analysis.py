import json
import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=API_KEY) if API_KEY else None


def analyze_evidence(
    content,
    indicators,
    url_analysis,
    threat_intelligence,
    email_analysis=None,
    file_analysis=None,
):
    if not client:
        return {
            "status": "unavailable",
            "threat_score": 0,
            "verdict": "Inconclusive",
            "confidence": 0,
            "reasoning": "Gemini API key is not configured.",
            "insufficient_evidence": True,
        }

    evidence_bundle = {
        "submitted_content": content,
        "indicators": indicators,
        "url_analysis": url_analysis,
        "threat_intelligence": threat_intelligence,
        "email_analysis": email_analysis,
        "file_analysis": file_analysis,
    }

    prompt = f"""
You are a cybersecurity evidence investigator.

Analyze only the evidence supplied below.

Rules:
- Use ONLY facts explicitly contained in the supplied evidence.
- Do not use prior knowledge, general knowledge, or remembered facts about any domain, company, service, or URL.
- Do not invent external evidence.
- Do not invent malware detections.
- Do not claim that a domain is well-known, legitimate, reserved, official, popular, trusted, or associated with a particular organization unless the supplied evidence explicitly says so.
- Do not speculate about why a reputation score or detection result has a particular value.
- HTTPS is only a transport-security observation and does not prove legitimacy.
- Zero VirusTotal detections does not prove that something is safe.
- "Undetected" must not be treated as "harmless".
- Absence of malicious evidence is not positive evidence of safety.
- If the submitted content contains no cybersecurity-relevant evidence and no indicators or threat-intelligence evidence are available, return Inconclusive rather than Low Risk.
- Low Risk requires actual supporting security evidence; it must not be based only on the absence of suspicious evidence.
- Distinguish suspicious characteristics from confirmed malicious evidence.
- Base the threat score, verdict, confidence, and reasoning only on the supplied evidence.
- If the available evidence cannot support a confident conclusion, return Inconclusive.
- Threat score must be an integer between 0 and 100.
- Confidence must be an integer between 0 and 100.
- Return JSON only.

Verdict policy:
- Low Risk: the supplied evidence contains affirmative benign indicators and no meaningful suspicious or malicious evidence. This does NOT mean guaranteed safe.
- Suspicious: the supplied evidence contains suspicious characteristics but does not establish strong malicious evidence.
- High Risk: the supplied evidence contains strong or confirmed malicious evidence.
- Inconclusive: the supplied evidence is too limited, absent, conflicting, or weak to support a meaningful security assessment.

Additional rules:
- VirusTotal harmless classifications are affirmative benign evidence.
- VirusTotal undetected classifications are NOT harmless evidence.
- Zero malicious or suspicious detections alone does not prove safety.
- When VirusTotal reports harmless classifications, zero malicious detections, zero suspicious detections, and no other suspicious findings are present, Low Risk is permitted.
- Confidence represents the strength of evidence supporting the risk assessment, not confidence in being uncertain.
- A From display name is only a claimed sender identity; do not treat it as verified identity.
- A routing IP, country, ASN, or network identifies observed mail infrastructure and must not be presented as the sender person's physical location.
- SPF, DKIM, and DMARC values parsed from uploaded message headers are header-reported evidence, not independent verification unless the evidence explicitly says they were verified.
- A Reply-To or Return-Path mismatch is an indicator that requires context; it is not by itself proof of spoofing or malicious intent.
- Static file findings describe directly observed structure or indicators. Active content, embedded objects, external relationships, forms, scripts, redirects, or obfuscation primitives are not by themselves proof of malware.
- Never claim an uploaded file was executed. Static analysis only is performed.

Return exactly this structure:

{{
  "threat_score": 0,
  "verdict": "Low Risk",
  "confidence": 0,
  "reasoning": "Briefly cite the specific supplied evidence that supports the conclusion.",
  "insufficient_evidence": false
}}

Allowed verdicts:
Low Risk
Suspicious
High Risk
Inconclusive

Evidence:
{json.dumps(evidence_bundle, indent=2)}
"""

    try:
        models = [
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash",
        ]

        response = None
        last_error = None

        for model in models:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0,
                    ),
                )

                print(f"Gemini model used: {model}")
                break

            except Exception as error:
                print(f"Gemini model failed ({model}):", error)
                last_error = error

        if response is None:
            raise last_error

        text = response.text.strip()

        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]

        if text.endswith("```"):
            text = text[:-3]

        result = json.loads(text.strip())

        no_indicators = (
            not indicators.get("urls")
            and not indicators.get("domains")
            and not indicators.get("emails")
        )

        email_security_evidence = bool(
            email_analysis
            and (
                email_analysis.get("warnings")
                or email_analysis.get("originating_ip")
                or any(
                    email_analysis.get(
                        "authentication",
                        {},
                    ).get(name) != "not_reported"
                    for name in ("spf", "dkim", "dmarc")
                )
            )
        )

        file_security_evidence = bool(
            file_analysis
            and file_analysis.get("findings")
        )

        no_security_evidence = (
            no_indicators
            and not url_analysis
            and not threat_intelligence
            and not email_security_evidence
            and not file_security_evidence
        )

        if (
            no_security_evidence
            and result.get("verdict") == "Inconclusive"
        ):
            return {
                "status": "success",
                "threat_score": 0,
                "verdict": "Inconclusive",
                "confidence": 0,
                "reasoning": (
                    "No cybersecurity indicators or supporting "
                    "threat-intelligence evidence were available, "
                    "so there is insufficient evidence for a "
                    "definitive security assessment."
                ),
                "insufficient_evidence": True,
            }

        if (
            no_security_evidence
            and result.get("verdict") == "Low Risk"
        ):
            return {
                "status": "success",
                "threat_score": 0,
                "verdict": "Inconclusive",
                "confidence": 0,
                "reasoning": (
                    "No cybersecurity indicators or supporting "
                    "threat-intelligence evidence were available, "
                    "so there is insufficient evidence to classify "
                    "the content as low risk."
                ),
                "insufficient_evidence": True,
            }

        return {
            "status": "success",
            "threat_score": max(
                0,
                min(100, int(result["threat_score"])),
            ),
            "verdict": result["verdict"],
            "confidence": max(
                0,
                min(100, int(result["confidence"])),
            ),
            "reasoning": result["reasoning"],
            "insufficient_evidence": result.get(
                "insufficient_evidence",
                False,
            ),
        }

    except Exception as error:
        print("Gemini analysis failed:", error)

        return {
            "status": "error",
            "threat_score": 0,
            "verdict": "Inconclusive",
            "confidence": 0,
            "reasoning": (
                "AI assessment is temporarily unavailable. "
                "The collected cybersecurity evidence remains available."
            ),
            "insufficient_evidence": True,
        }

def challenge_assessment(
    content,
    indicators,
    url_analysis,
    threat_intelligence,
    original_assessment,
    email_analysis=None,
    file_analysis=None,
):
    if not client:
        return {
            "status": "unavailable",
            "revised_verdict": original_assessment["verdict"],
            "revised_confidence": original_assessment["confidence"],
            "counter_evidence": [],
            "reasoning": "Gemini API key is not configured.",
            "conclusion_changed": False,
        }

    evidence_bundle = {
        "submitted_content": content,
        "indicators": indicators,
        "url_analysis": url_analysis,
        "threat_intelligence": threat_intelligence,
        "email_analysis": email_analysis,
        "file_analysis": file_analysis,
        "original_assessment": original_assessment,
    }

    prompt = f"""
You are performing an adversarial review of a cybersecurity assessment.

Your job is NOT to automatically disagree with the original conclusion.

Instead, examine the supplied evidence and determine whether any evidence:
- weakens the original conclusion,
- contradicts the original conclusion,
- was overlooked,
- was given too much weight,
- or introduces uncertainty.

Rules:
- Use ONLY facts explicitly contained in the supplied evidence.
- Do not use prior knowledge or external knowledge.
- Do not invent threat intelligence.
- Do not invent malware detections.
- Do not invent counter-evidence.
- Zero VirusTotal detections does not prove safety.
- Undetected does not mean harmless.
- HTTPS does not prove legitimacy.
- A claimed sender name is not verified identity.
- Routing geography describes mail infrastructure, not the sender person's physical location.
- Header-reported SPF, DKIM, and DMARC values are not independent verification unless explicitly marked as verified.
- Static file indicators do not prove malware or compromise, and the uploaded artifact was not executed.
- If no meaningful counter-evidence exists, say so.
- A revised confidence must be between 0 and 100.
- The revised verdict must be one of:
  Low Risk
  Suspicious
  High Risk
  Inconclusive
- Return JSON only.

Return exactly:

{{
  "revised_verdict": "Low Risk",
  "revised_confidence": 0,
  "counter_evidence": [
    "Specific evidence that weakens or challenges the original conclusion"
  ],
  "reasoning": "Brief explanation of the adversarial review.",
  "conclusion_changed": false
}}

Evidence and original assessment:
{json.dumps(evidence_bundle, indent=2)}
"""

    try:
        models = [
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash",
        ]

        response = None
        last_error = None

        for model in models:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0,
                    ),
                )

                print(f"Challenge model used: {model}")
                break

            except Exception as error:
                print(f"Challenge model failed ({model}):", error)
                last_error = error

        if response is None:
            raise last_error

        text = response.text.strip()

        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]

        if text.endswith("```"):
            text = text[:-3]

        result = json.loads(text.strip())

        return {
            "status": "success",
            "revised_verdict": result["revised_verdict"],
            "revised_confidence": max(
                0,
                min(100, int(result["revised_confidence"])),
            ),
            "counter_evidence": result.get(
                "counter_evidence",
                [],
            ),
            "reasoning": result["reasoning"],
            "conclusion_changed": result.get(
                "conclusion_changed",
                False,
            ),
        }

    except Exception as error:
        print("Challenge analysis failed:", error)

        return {
            "status": "error",
            "revised_verdict": original_assessment["verdict"],
            "revised_confidence": original_assessment["confidence"],
            "counter_evidence": [],
            "reasoning": (
                "The conclusion challenge is temporarily unavailable."
            ),
            "conclusion_changed": False,
        }
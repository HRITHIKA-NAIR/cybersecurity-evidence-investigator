import json
import os

from dotenv import load_dotenv
from google import genai

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=API_KEY) if API_KEY else None


def analyze_evidence(
    content,
    indicators,
    url_analysis,
    threat_intelligence,
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
- Distinguish suspicious characteristics from confirmed malicious evidence.
- Base the threat score, verdict, confidence, and reasoning only on the supplied evidence.
- If the available evidence cannot support a confident conclusion, return Inconclusive.
- Threat score must be an integer between 0 and 100.
- Confidence must be an integer between 0 and 100.
- Return JSON only.

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
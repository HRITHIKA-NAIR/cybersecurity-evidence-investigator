import json

from app.integrations.gemini import (
    available,
    generate_json,
)
from app.models import (
    AssessmentResult,
    ChallengeResult,
)


def _no_security_evidence(
    indicators,
    threat_intelligence,
    email_analysis,
    file_analysis,
    attack_findings,
) -> bool:
    no_indicators = not any(
        indicators.get(key)
        for key in (
            "urls",
            "domains",
            "emails",
        )
    )
    email_signal = bool(
        email_analysis
        and (
            email_analysis.get("warnings")
            or email_analysis.get(
                "originating_ip"
            )
            or any(
                (
                    status
                    and status
                    != "not_reported"
                )
                for status in (
                    email_analysis.get(
                        "authentication",
                        {},
                    ).get(name)
                    for name in (
                        "spf",
                        "dkim",
                        "dmarc",
                    )
                )
            )
        )
    )
    file_signal = bool(
        file_analysis
        and file_analysis.get(
            "findings"
        )
    )

    return (
        no_indicators
        and not threat_intelligence
        and not email_signal
        and not file_signal
        and not attack_findings
    )


def analyze_evidence(
    content,
    indicators,
    url_analysis,
    threat_intelligence,
    email_analysis=None,
    file_analysis=None,
    evidence_items=None,
    attack_findings=None,
    attack_chain=None,
):
    if not available():
        return {
            "status": "unavailable",
            "threat_score": 0,
            "verdict": "Inconclusive",
            "confidence": 0,
            "reasoning": (
                "Gemini API key is not configured."
            ),
            "insufficient_evidence": True,
        }

    evidence_bundle = {
        "submitted_content": content,
        "indicators": indicators,
        "url_analysis": url_analysis,
        "threat_intelligence": (
            threat_intelligence
        ),
        "email_analysis": email_analysis,
        "file_analysis": file_analysis,
        "evidence_items": (
            evidence_items or []
        ),
        "attack_findings": (
            attack_findings or []
        ),
        "attack_chain": (
            attack_chain or []
        ),
    }

    prompt = f"""
You are a cybersecurity evidence investigator.

Analyze only the supplied evidence.

Rules:
- Use ONLY facts explicitly contained in the evidence bundle.
- Do not use prior knowledge or remembered facts about submitted entities.
- Do not invent external evidence, malware detections, ownership, reputation, identity, or attack stages.
- The supplied attack_findings are structured multi-label hypotheses produced by deterministic detectors. Multiple findings may be simultaneously relevant.
- Do not invent new attack-finding labels and do not upgrade a finding beyond its supplied status/evidence.
- The supplied attack_chain contains only evidence-backed stages. Do not fill missing stages from assumptions.
- HTTPS is transport evidence only and does not prove legitimacy.
- VirusTotal undetected is not harmless. Zero malicious detections alone does not prove safety.
- Static file findings do not prove runtime behavior; uploaded artifacts were not executed.
- QR payloads and URL heuristics are indicators unless stronger supplied evidence exists.
- Header-reported SPF/DKIM/DMARC is not independently verified unless explicitly stated.
- Claimed email identity and routing geography are not verified human identity/location.
- Redirect failures/timeouts are not benign or malicious evidence by themselves.
- Low Risk requires affirmative benign evidence and no meaningful suspicious evidence.
- Prefer Inconclusive when evidence is absent, weak, or conflicting.
- Threat score and confidence must be integers from 0 to 100.
- Return JSON only.

Verdicts:
- Low Risk
- Suspicious
- High Risk
- Inconclusive

Return exactly:
{{
  "threat_score": 0,
  "verdict": "Inconclusive",
  "confidence": 0,
  "reasoning": "Brief evidence-grounded explanation.",
  "insufficient_evidence": false
}}

Evidence:
{json.dumps(evidence_bundle, indent=2)}
"""

    try:
        raw_result = generate_json(
            prompt,
            label="Gemini analysis",
        )
        result = (
            AssessmentResult.model_validate(
                raw_result
            )
        )

        no_evidence = _no_security_evidence(
            indicators,
            threat_intelligence,
            email_analysis,
            file_analysis,
            attack_findings or [],
        )

        if (
            no_evidence
            and result.verdict
            in {
                "Low Risk",
                "Inconclusive",
            }
        ):
            return {
                "status": "success",
                "threat_score": 0,
                "verdict": "Inconclusive",
                "confidence": 0,
                "reasoning": (
                    "No cybersecurity indicators or "
                    "supporting threat-intelligence "
                    "evidence were available, so "
                    "there is insufficient evidence "
                    "for a definitive security "
                    "assessment."
                ),
                "insufficient_evidence": True,
            }

        return {
            "status": "success",
            **result.model_dump(),
        }

    except Exception as error:
        print(
            "Gemini analysis failed:",
            error,
        )

        return {
            "status": "error",
            "threat_score": 0,
            "verdict": "Inconclusive",
            "confidence": 0,
            "reasoning": (
                "AI assessment is temporarily "
                "unavailable. The collected "
                "cybersecurity evidence remains "
                "available."
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
    evidence_items=None,
    attack_findings=None,
    attack_chain=None,
):
    if not available():
        return {
            "status": "unavailable",
            "revised_verdict": (
                original_assessment[
                    "verdict"
                ]
            ),
            "revised_confidence": (
                original_assessment[
                    "confidence"
                ]
            ),
            "counter_evidence": [],
            "reasoning": (
                "Gemini API key is not "
                "configured."
            ),
            "conclusion_changed": False,
        }

    evidence_bundle = {
        "submitted_content": content,
        "indicators": indicators,
        "url_analysis": url_analysis,
        "threat_intelligence": (
            threat_intelligence
        ),
        "email_analysis": email_analysis,
        "file_analysis": file_analysis,
        "evidence_items": (
            evidence_items or []
        ),
        "attack_findings": (
            attack_findings or []
        ),
        "attack_chain": (
            attack_chain or []
        ),
        "original_assessment": (
            original_assessment
        ),
    }

    prompt = f"""
You are performing an adversarial review of a cybersecurity assessment.

Review the same evidence without automatically disagreeing.

Check whether supplied evidence:
- weakens or contradicts the original conclusion,
- was overlooked,
- was given too much weight,
- or introduces material uncertainty.

Rules:
- Use ONLY the supplied evidence.
- Do not invent evidence, threat intelligence, identity facts, attack findings, or attack-chain stages.
- Treat supplied multi-label findings according to their status, evidence references, and limitations.
- Do not treat static indicators as proof of runtime behavior.
- Zero VirusTotal detections does not prove safety; undetected is not harmless.
- HTTPS does not prove legitimacy.
- Claimed sender identity is not verified identity.
- Header-reported SPF/DKIM/DMARC is not independently verified unless explicitly stated.
- QR payloads and URL heuristics are indicators unless stronger evidence exists.
- Redirect errors/timeouts do not prove safety or maliciousness.
- If no meaningful counter-evidence exists, say so.
- Revised confidence must be 0 to 100.
- Revised verdict must be Low Risk, Suspicious, High Risk, or Inconclusive.
- Return JSON only.

Return exactly:
{{
  "revised_verdict": "Inconclusive",
  "revised_confidence": 0,
  "counter_evidence": [],
  "reasoning": "Brief evidence-grounded adversarial review.",
  "conclusion_changed": false
}}

Evidence and original assessment:
{json.dumps(evidence_bundle, indent=2)}
"""

    try:
        raw_result = generate_json(
            prompt,
            label="Challenge",
        )
        result = (
            ChallengeResult.model_validate(
                raw_result
            )
        )

        return {
            "status": "success",
            **result.model_dump(),
        }

    except Exception as error:
        print(
            "Challenge analysis failed:",
            error,
        )

        return {
            "status": "error",
            "revised_verdict": (
                original_assessment[
                    "verdict"
                ]
            ),
            "revised_confidence": (
                original_assessment[
                    "confidence"
                ]
            ),
            "counter_evidence": [],
            "reasoning": (
                "The conclusion challenge is "
                "temporarily unavailable."
            ),
            "conclusion_changed": False,
        }

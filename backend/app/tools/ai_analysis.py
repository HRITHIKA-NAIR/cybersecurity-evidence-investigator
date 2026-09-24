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

    authentication = (
        email_analysis.get(
            "authentication",
            {},
        )
        if email_analysis
        else {}
    )
    auth_failure = any(
        str(
            authentication.get(
                name,
                "",
            )
        ).lower()
        in {
            "fail",
            "softfail",
            "temperror",
            "permerror",
        }
        for name in (
            "spf",
            "dkim",
            "dmarc",
        )
    )
    routing = (
        email_analysis.get(
            "routing_intelligence",
            {},
        )
        if email_analysis
        else {}
    )
    routing_signal = (
        routing.get("status") == "success"
        and (
            int(
                routing.get(
                    "malicious",
                    0,
                )
                or 0
            )
            > 0
            or int(
                routing.get(
                    "suspicious",
                    0,
                )
                or 0
            )
            > 0
        )
    )
    email_signal = bool(
        email_analysis
        and (
            email_analysis.get("warnings")
            or auth_failure
            or routing_signal
        )
    )
    file_signal = bool(
        file_analysis
        and file_analysis.get(
            "findings"
        )
    )
    threat_signal = any(
        result.get("status") == "success"
        and (
            int(
                result.get(
                    "malicious",
                    0,
                )
                or 0
            )
            > 0
            or int(
                result.get(
                    "suspicious",
                    0,
                )
                or 0
            )
            > 0
            or int(
                result.get(
                    "harmless",
                    0,
                )
                or 0
            )
            > 0
            or int(
                result.get(
                    "reputation",
                    0,
                )
                or 0
            )
            != 0
        )
        for result in threat_intelligence
    )

    return (
        no_indicators
        and not threat_signal
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
                "AI assessment is disabled or not configured."
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
            type(error).__name__,
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
            "revised_threat_score": (
                original_assessment[
                    "threat_score"
                ]
            ),
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
            "uncertainty": [
                "Challenge review was unavailable."
            ],
            "reasoning": (
                "AI review is disabled or not configured."
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
- Revised threat score and revised confidence must be integers from 0 to 100.
- Revised verdict must be Low Risk, Suspicious, High Risk, or Inconclusive.
- uncertainty must list material unknowns or evidence limitations; use [] only when none are material.
- Return JSON only.

Return exactly:
{{
  "revised_threat_score": 0,
  "revised_verdict": "Inconclusive",
  "revised_confidence": 0,
  "counter_evidence": [],
  "uncertainty": [],
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
            type(error).__name__,
        )

        return {
            "status": "error",
            "revised_threat_score": (
                original_assessment[
                    "threat_score"
                ]
            ),
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
            "uncertainty": [
                "Challenge review was unavailable."
            ],
            "reasoning": (
                "The conclusion challenge is "
                "temporarily unavailable."
            ),
            "conclusion_changed": False,
        }

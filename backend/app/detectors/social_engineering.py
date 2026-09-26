from __future__ import annotations

import re

RULES = (
    {
        "signal": "Urgency Pressure",
        "severity": "Medium",
        "confidence": 82,
        "patterns": (
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bact now\b",
            r"\bfinal notice\b",
            r"\bwithin\s+(?:24|48)\s+hours\b",
            r"\bexpires?\s+(?:today|soon)\b",
        ),
    },
    {
        "signal": "Fear or Account Threat",
        "severity": "Medium",
        "confidence": 84,
        "patterns": (
            r"\baccount\s+(?:will be\s+)?(?:suspended|locked|closed|disabled)\b",
            r"\bunauthori[sz]ed\s+(?:login|access|activity)\b",
            r"\bsecurity\s+alert\b",
            r"\bavoid\s+(?:suspension|closure|termination)\b",
        ),
    },
    {
        "signal": "Authority or Support Impersonation",
        "severity": "Medium",
        "confidence": 76,
        "patterns": (
            r"\b(?:it|technical)\s+support\b",
            r"\bhelp\s*desk\b",
            r"\bsecurity\s+team\b",
            r"\bsystem\s+administrator\b",
            r"\baccount\s+support\b",
        ),
    },
    {
        "signal": "Credential Request",
        "severity": "High",
        "confidence": 90,
        "patterns": (
            r"\b(?:enter|provide|confirm|verify|submit|update)\b[^\n]{0,45}\bpassword\b",
            r"\busername\s+and\s+password\b",
            r"\blogin\s+credentials?\b",
            r"\bsign\s*in\b[^\n]{0,45}\b(?:verify|confirm|secure)\b",
            r"\bverify\s+(?:your\s+)?account\b",
        ),
    },
    {
        "signal": "MFA Code Request",
        "severity": "High",
        "confidence": 94,
        "patterns": (
            r"\b(?:send|share|provide|enter|confirm)\b[^\n]{0,45}\b(?:otp|mfa|2fa)\b",
            r"\b(?:send|share|provide|enter|confirm)\b[^\n]{0,45}\bverification\s+code\b",
            r"\bone[- ]time\s+(?:password|code)\b",
        ),
    },
    {
        "signal": "Payment Change or Financial Pressure",
        "severity": "High",
        "confidence": 88,
        "patterns": (
            r"\bchange\b[^\n]{0,45}\b(?:bank|payment)\s+(?:details|account)\b",
            r"\bwire\s+transfer\b",
            r"\b(?:urgent|immediate)\b[^\n]{0,45}\bpayment\b",
            r"\bgift\s+cards?\b",
            r"\bcrypto(?:currency)?\s+payment\b",
            r"\binvoice\b[^\n]{0,45}\b(?:new|updated|different)\s+(?:bank|payment)\b",
        ),
    },
)


def detect_social_engineering(
    content: str,
) -> list[dict]:
    text = content or ""
    signals = []

    for rule in RULES:
        matches = []

        for pattern in rule["patterns"]:
            for match in re.finditer(
                pattern,
                text,
                re.IGNORECASE,
            ):
                value = match.group(0).strip()

                if value and value not in matches:
                    matches.append(value)

        if not matches:
            continue

        signals.append(
            {
                "signal": rule["signal"],
                "category": "Social Engineering",
                "severity": rule["severity"],
                "status": "Indicator Present",
                "confidence": rule["confidence"],
                "matched_text": matches[:5],
                "message": (
                    f"{rule['signal']} language was "
                    "detected in the submitted content."
                ),
            }
        )

    return signals

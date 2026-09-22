from __future__ import annotations

import re

RULES = (
    {
        "attack_type": "SQL Injection Indicator",
        "category": "Web Attack Evidence",
        "severity": "Medium",
        "confidence": 78,
        "patterns": (
            r"(?i)\bunion\s+select\b",
            r"(?i)['\"]\s*or\s+1\s*=\s*1",
            r"(?i)\bsleep\s*\(\s*\d+\s*\)",
        ),
    },
    {
        "attack_type": "XSS Indicator",
        "category": "Web Attack Evidence",
        "severity": "Medium",
        "confidence": 82,
        "patterns": (
            r"(?i)<script\b",
            r"(?i)javascript\s*:",
            r"(?i)\bon(?:error|load|click)\s*=",
        ),
    },
    {
        "attack_type": "Path Traversal Indicator",
        "category": "Web Attack Evidence",
        "severity": "Medium",
        "confidence": 78,
        "patterns": (
            r"(?:\.\./){2,}",
            r"(?i)(?:%2e%2e(?:%2f|/)){2,}",
        ),
    },
    {
        "attack_type": "Command Injection Indicator",
        "category": "Web Attack Evidence",
        "severity": "High",
        "confidence": 76,
        "patterns": (
            r"(?i)(?:;|&&|\|)\s*(?:curl|wget|powershell|cmd\.exe|sh\b|bash\b)",
        ),
    },
)


def detect_web_attack_indicators(
    content: str,
) -> list[dict]:
    findings = []

    for rule in RULES:
        matches = []

        for pattern in rule["patterns"]:
            for match in re.finditer(
                pattern,
                content or "",
            ):
                value = match.group(0)

                if value not in matches:
                    matches.append(value)

        if matches:
            findings.append(
                {
                    "attack_type": rule[
                        "attack_type"
                    ],
                    "category": rule[
                        "category"
                    ],
                    "severity": rule[
                        "severity"
                    ],
                    "status": (
                        "Indicator Present"
                    ),
                    "confidence": rule[
                        "confidence"
                    ],
                    "matched_text": (
                        matches[:5]
                    ),
                    "limitations": [
                        "Pattern observed only in "
                        "submitted evidence; no "
                        "external target was probed."
                    ],
                }
            )

    return findings

"""Deterministic, explainable risk assessment used when AI is off/unavailable,
and as an evidence-grounded baseline the AI model refines.

No network, no randomness: same evidence -> same answer. It never invents
facts; every sentence is derived from a collected finding.
"""
from __future__ import annotations

_LOOKALIKE_MARKERS = ("imitates", "typosquat", "look-alike", "mixes alphabets", "impersonation", "impersonat")


def _url_flags(url_analysis: list[dict]) -> tuple[list[str], list[str], list[str]]:
    suspicious, warnings, positives = [], [], []
    for result in url_analysis:
        for item in result.get("findings", []):
            bucket = {"suspicious": suspicious, "warning": warnings, "positive": positives}.get(item.get("type"))
            if bucket is not None and item["message"] not in bucket:
                bucket.append(item["message"])
    return suspicious, warnings, positives


def _threat_counts(threat_intelligence: list[dict]) -> tuple[int, int, int, bool]:
    malicious = suspicious = harmless = 0
    answered = False
    for item in threat_intelligence:
        if item.get("status") == "success":
            answered = True
            malicious += int(item.get("malicious", 0) or 0)
            suspicious += int(item.get("suspicious", 0) or 0)
            harmless += int(item.get("harmless", 0) or 0)
    return malicious, suspicious, harmless, answered


def _pages(url_analysis: list[dict]) -> tuple[int, int]:
    inspected = failed = 0
    for result in url_analysis:
        status = (result.get("page_analysis") or {}).get("status")
        if status == "inspected":
            inspected += 1
        elif status is not None:
            failed += 1
    return inspected, failed


def baseline_assessment(
    indicators: dict,
    url_analysis: list[dict],
    threat_intelligence: list[dict],
    email_analysis: dict | None,
    file_analysis: dict | None,
    attack_findings: list[dict],
) -> dict:
    suspicious, warnings, positives = _url_flags(url_analysis)
    malicious, vt_suspicious, harmless, vt_answered = _threat_counts(threat_intelligence)
    inspected, not_inspected = _pages(url_analysis)

    high = [f for f in attack_findings if f.get("severity") in {"High", "Critical"}]
    medium = [f for f in attack_findings if f.get("severity") == "Medium"]
    email_warnings = list((email_analysis or {}).get("warnings") or [])
    file_findings = list((file_analysis or {}).get("findings") or [])

    has_input = bool(
        indicators.get("urls") or indicators.get("emails") or indicators.get("domains")
        or email_analysis or file_analysis or attack_findings
    )
    if not has_input:
        return {
            "status": "baseline",
            "threat_score": 0,
            "verdict": "Inconclusive",
            "confidence": 0,
            "reasoning": (
                "Nothing checkable was found in what you submitted: no web address, "
                "email address, file or recognisable warning sign. Paste the full link "
                "or message, or upload the original file, and run the check again."
            ),
            "insufficient_evidence": True,
        }

    score = 0
    lookalike = [m for m in suspicious + warnings if any(k in m.lower() for k in _LOOKALIKE_MARKERS)]
    score += min(45, 40 * bool(lookalike))
    score += min(50, 18 * len([m for m in suspicious if m not in lookalike]))
    score += min(16, 6 * len([m for m in warnings if m not in lookalike]))
    if malicious:
        score += min(60, 35 + 5 * malicious)
    elif vt_suspicious:
        score += 15
    score += min(30, 15 * len(high)) + min(12, 6 * len(medium))
    score += min(24, 8 * len(email_warnings)) + min(24, 8 * len(file_findings))
    score = max(0, min(100, score))

    benign_evidence = bool(
        inspected and not suspicious and not warnings and not high
        and not email_warnings and not file_findings and not malicious and not vt_suspicious
    )
    if score >= 70:
        verdict = "High Risk"
    elif score >= 30:
        verdict = "Suspicious"
    elif benign_evidence or (vt_answered and harmless and not suspicious and not warnings and not malicious):
        verdict = "Low Risk"
    elif score >= 15:
        verdict = "Suspicious"
    else:
        verdict = "Inconclusive"

    confidence = 35 + 12 * bool(inspected) + 10 * bool(vt_answered) + 8 * bool(indicators.get("urls"))
    confidence += min(20, 7 * (len(suspicious) + len(high)))
    confidence = min(85, confidence)
    if verdict == "Low Risk":
        confidence = min(70, confidence)
    if verdict == "Inconclusive":
        confidence = min(confidence, 30)

    # ---- long-form, evidence-grounded explanation -------------------------
    checked = []
    if indicators.get("urls"):
        checked.append(f"{len(indicators['urls'])} web address(es): structure, spelling against well-known brands, redirects")
    if inspected:
        checked.append(f"the actual content of {inspected} page(s): forms, hidden links, link targets, scripts")
    if vt_answered:
        checked.append("VirusTotal reputation")
    if email_analysis:
        checked.append("the email headers and content")
    if file_analysis:
        checked.append("the uploaded file (static inspection, never executed)")
    if not checked:
        checked.append("the text you submitted")

    found = [*lookalike, *[m for m in suspicious if m not in lookalike]][:6]
    if malicious:
        found.append(f"{malicious} security engine(s) on VirusTotal flag this as malicious")
    found += [f"{f.get('attack_type')} ({f.get('severity')})" for f in high[:3]]
    minor = [m for m in warnings if m not in lookalike][:4]

    parts = ["What we checked: " + "; ".join(checked) + "."]
    if found:
        parts.append("What raised concern: " + " | ".join(found) + ".")
    if minor:
        parts.append("Smaller warning signs: " + " | ".join(minor) + ".")
    if positives and not found:
        parts.append("What looked normal: " + positives[-1] + ".")

    limits = ["we do not run page scripts or open files", "results reflect this moment only"]
    if not vt_answered:
        limits.append("no reputation database answered")
    if not_inspected and not inspected:
        limits.append("the page could not be fetched, so its content was not seen")
    parts.append("What we could not check: " + "; ".join(limits) + ".")

    if verdict == "High Risk":
        parts.append("Bottom line: treat this as dangerous. Do not enter passwords or payment details, and do not open it again.")
    elif verdict == "Suspicious":
        parts.append("Bottom line: several warning signs point to a possible scam. Do not sign in or pay through it; reach the organisation only through its official website or app.")
    elif verdict == "Low Risk":
        parts.append("Bottom line: no warning signs were found in the checks above, which lowers but does not remove risk. Still avoid entering sensitive data unless you reached the site yourself.")
    else:
        parts.append("Bottom line: there is not enough evidence to say either way. Do not treat that as safe.")

    return {
        "status": "baseline",
        "threat_score": score,
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": "\n\n".join(parts),
        "insufficient_evidence": verdict == "Inconclusive",
    }

from __future__ import annotations

from app.database import (
    DatabaseOperationError,
    save_investigation,
)
from app.detectors.social_engineering import (
    detect_social_engineering,
)
from app.detectors.web_attack_detector import (
    detect_web_attack_indicators,
)
from app.services.attack_chain import (
    build_attack_chain,
    chain_as_dicts,
)
from app.services.attack_classifier import (
    classify_attack_findings,
    findings_as_dicts,
)
from app.services.evidence_service import (
    build_evidence_items,
    evidence_as_dicts,
    evidence_summaries,
)
from app.services.threat_service import (
    gather_threat_intelligence,
)
from app.tools.ai_analysis import analyze_evidence
from app.detectors.lookalike import check_hostname
from app.tools.indicators import extract_indicators
from app.tools.url_investigation import investigate_url
from app.tools.virustotal import check_ip


MAX_PAGE_INSPECTIONS = 3


def _email_domain_results(indicators: dict, url_results: list[dict]) -> list[dict]:
    """Look-alike check for sender/recipient domains that are not URLs."""
    covered = {result.get("hostname") for result in url_results}
    extra = []
    for address in indicators.get("emails", []):
        domain = address.rsplit("@", 1)[1].lower()
        if domain in covered:
            continue
        covered.add(domain)
        findings = check_hostname(domain)
        if findings:
            extra.append({
                "url": f"email address {address}",
                "normalized_url": None,
                "hostname": domain,
                "scheme": "",
                "registered_domain": domain,
                "subdomain": "",
                "findings": [
                    {"type": item["type"], "message": f"Email domain: {item['message']}"}
                    for item in findings
                ],
                "redirect_analysis": {
                    "status": "not_applicable",
                    "reason": "Email addresses are not visited.",
                    "hops": [],
                    "redirect_count": 0,
                },
            })
    return extra


def _merge_file_indicators(
    indicators: dict,
    file_analysis: dict | None,
) -> None:
    if not file_analysis:
        return

    urls = file_analysis.get(
        "urls",
        [],
    )

    if not urls:
        return

    derived = extract_indicators(
        "\n".join(urls)
    )

    for key in (
        "urls",
        "domains",
        "emails",
    ):
        for item in derived[key]:
            if item not in indicators[key]:
                indicators[key].append(item)


def _enrich_email(
    email_analysis: dict | None,
) -> dict | None:
    if not email_analysis:
        return None

    enriched = dict(email_analysis)
    originating_ip = enriched.get(
        "originating_ip"
    )

    if originating_ip:
        enriched[
            "routing_intelligence"
        ] = check_ip(originating_ip)

    return enriched


def run_investigation(
    content: str,
    file_info: dict | None = None,
    email_analysis: dict | None = None,
    file_analysis: dict | None = None,
    *, owner_id: str | None = None,
    category: str | None = None,
) -> dict:
    indicators = extract_indicators(
        content,
        link_mode=category == "link",
    )
    _merge_file_indicators(
        indicators,
        file_analysis,
    )

    url_results = [
        investigate_url(url)
        if index < MAX_PAGE_INSPECTIONS
        else investigate_url(url, inspect=False)
        for index, url in enumerate(indicators["urls"])
    ]
    url_results.extend(_email_domain_results(indicators, url_results))

    threat_results = (
        gather_threat_intelligence(
            indicators,
            file_info,
        )
    )

    email_analysis = _enrich_email(
        email_analysis
    )
    social_signals = (
        detect_social_engineering(
            content
        )
    )
    web_attack_signals = (
        detect_web_attack_indicators(
            content
        )
    )

    evidence_models = build_evidence_items(
        content=content,
        indicators=indicators,
        url_analysis=url_results,
        threat_intelligence=threat_results,
        file_info=file_info,
        email_analysis=email_analysis,
        file_analysis=file_analysis,
        social_signals=social_signals,
        web_attack_signals=(
            web_attack_signals
        ),
    )
    finding_models = (
        classify_attack_findings(
            evidence_models
        )
    )
    chain_models = build_attack_chain(
        evidence_models,
        finding_models,
    )

    evidence_items = evidence_as_dicts(
        evidence_models
    )
    attack_findings = findings_as_dicts(
        finding_models
    )
    attack_chain = chain_as_dicts(
        chain_models
    )

    ai_result = analyze_evidence(
        content,
        indicators,
        url_results,
        threat_results,
        email_analysis,
        file_analysis,
        evidence_items,
        attack_findings,
        attack_chain,
    )

    persistence = {
        "status": "saved",
        "message": None,
    }
    investigation_id = None

    try:
        investigation_id = save_investigation(
            content,
            indicators,
            url_results,
            threat_results,
            ai_result,
            file_info=file_info,
            email_analysis=email_analysis,
            file_analysis=file_analysis,
            evidence_items=evidence_items,
            attack_findings=attack_findings,
            attack_chain=attack_chain,
            owner_id=owner_id,
        )
    except DatabaseOperationError:
        persistence = {
            "status": "unavailable",
            "message": (
                "Investigation completed, but "
                "persistent history is currently "
                "unavailable."
            ),
        }

    evidence = [
        (
            "Extracted "
            f"{len(indicators['urls'])} URL(s)"
        ),
        (
            "Extracted "
            f"{len(indicators['domains'])} domain(s)"
        ),
        (
            "Extracted "
            f"{len(indicators['emails'])} "
            "email address(es)"
        ),
        *evidence_summaries(
            evidence_models
        ),
    ]

    return {
        "status": "completed",
        "investigation_id": investigation_id,
        "persistence": persistence,
        "file_info": file_info,
        "email_analysis": email_analysis,
        "file_analysis": file_analysis,
        "indicators": indicators,
        "url_analysis": url_results,
        "threat_intelligence": threat_results,
        "evidence_items": evidence_items,
        "attack_findings": attack_findings,
        "attack_chain": attack_chain,
        "threat_score": ai_result[
            "threat_score"
        ],
        "verdict": ai_result[
            "verdict"
        ],
        "confidence": ai_result[
            "confidence"
        ],
        "reasoning": ai_result[
            "reasoning"
        ],
        "insufficient_evidence": (
            ai_result[
                "insufficient_evidence"
            ]
        ),
        "evidence": evidence,
        "stages": {
            "extract_indicators": True,
            "analyze_url": True,
            "investigate_domain": True,
            "gather_evidence": True,
            "classify_attacks": True,
            "build_attack_chain": True,
            "counter_evidence": False,
            "calculate_assessment": (
                ai_result["status"]
                == "success"
            ),
        },
    }

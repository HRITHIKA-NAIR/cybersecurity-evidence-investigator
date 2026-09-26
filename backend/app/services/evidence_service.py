from __future__ import annotations

from app.models import EvidenceItem
from app.services.evidence_builder import (
    EvidenceBuilder,
)
from app.services.evidence_collectors import (
    collect_email_evidence,
    collect_file_evidence,
    collect_threat_evidence,
    collect_url_evidence,
)


def _collect_indicators(
    builder: EvidenceBuilder,
    indicators: dict,
) -> None:
    for url in indicators.get(
        "urls",
        [],
    ):
        builder.add(
            "indicator_url",
            "indicator_extractor",
            url,
            summary=(
                f"Extracted URL: {url}"
            ),
        )

    for domain in indicators.get(
        "domains",
        [],
    ):
        builder.add(
            "indicator_domain",
            "indicator_extractor",
            domain,
            summary=(
                f"Extracted domain: "
                f"{domain}"
            ),
        )

    for address in indicators.get(
        "emails",
        [],
    ):
        builder.add(
            "indicator_email",
            "indicator_extractor",
            address,
            summary=(
                "Extracted email address: "
                f"{address}"
            ),
        )


    truncated = indicators.get(
        "truncated",
        {},
    )
    limited = [
        key
        for key, value in truncated.items()
        if value
    ]

    if limited:
        builder.add(
            "analysis_limitation",
            "indicator_extractor",
            {
                "truncated_categories": limited,
            },
            summary=(
                "Indicator extraction was bounded "
                "for: "
                + ", ".join(limited)
            ),
        )


def build_evidence_items(
    *,
    content: str,
    indicators: dict,
    url_analysis: list[dict],
    threat_intelligence: list[dict],
    file_info: dict | None = None,
    email_analysis: dict | None = None,
    file_analysis: dict | None = None,
    social_signals: list[dict] | None = None,
    web_attack_signals: list[dict] | None = None,
) -> list[EvidenceItem]:
    builder = EvidenceBuilder()

    collect_file_evidence(
        builder,
        file_info,
        file_analysis,
    )
    _collect_indicators(
        builder,
        indicators,
    )
    collect_url_evidence(
        builder,
        url_analysis,
    )
    collect_email_evidence(
        builder,
        email_analysis,
    )
    collect_threat_evidence(
        builder,
        threat_intelligence,
    )

    for signal in social_signals or []:
        builder.add(
            "social_engineering",
            "social_engineering",
            signal,
            confidence=(
                signal.get(
                    "confidence",
                    80,
                )
                / 100
            ),
            summary=signal.get(
                "message"
            ),
        )


    for signal in web_attack_signals or []:
        builder.add(
            "web_attack",
            "web_attack_detector",
            signal,
            confidence=(
                signal.get(
                    "confidence",
                    75,
                )
                / 100
            ),
            summary=(
                "Submitted evidence contains "
                f"{signal['attack_type']}."
            ),
        )

    if not content.strip():
        builder.add(
            "analysis_limitation",
            "ingestion",
            "No extractable text content.",
        )

    return builder.items


def evidence_as_dicts(
    evidence_items: list[EvidenceItem],
) -> list[dict]:
    return [
        item.model_dump()
        for item in evidence_items
    ]


def evidence_summaries(
    evidence_items: list[EvidenceItem],
) -> list[str]:
    summaries = []

    for item in evidence_items:
        summary = item.provenance.get(
            "summary"
        )

        if (
            summary
            and summary not in summaries
        ):
            summaries.append(summary)

    return summaries

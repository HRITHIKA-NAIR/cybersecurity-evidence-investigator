from __future__ import annotations

from app.models import EvidenceItem


class EvidenceBuilder:
    def __init__(self):
        self.items: list[EvidenceItem] = []

    def add(
        self,
        evidence_type: str,
        source: str,
        value,
        *,
        confidence: float = 1.0,
        artifact_id: str | None = None,
        summary: str | None = None,
        provenance: dict | None = None,
    ) -> str:
        evidence_id = (
            f"ev-{len(self.items) + 1:04d}"
        )
        metadata = dict(
            provenance or {}
        )

        if summary:
            metadata["summary"] = summary

        self.items.append(
            EvidenceItem(
                id=evidence_id,
                type=evidence_type,
                source=source,
                value=value,
                confidence=confidence,
                artifact_id=artifact_id,
                provenance=metadata,
            )
        )
        return evidence_id


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
) -> list[EvidenceItem]:
    builder = EvidenceBuilder()
    artifact_id = "artifact-1" if file_info else None

    if file_info:
        builder.add(
            "artifact",
            "ingestion",
            file_info,
            artifact_id=artifact_id,
            summary=(
                f"File: {file_info['filename']} "
                f"({file_info['extension']}, "
                f"{file_info['size_bytes']} bytes)"
            ),
        )

    for url in indicators.get(
        "urls",
        [],
    ):
        builder.add(
            "indicator_url",
            "indicator_extractor",
            url,
            summary=f"Extracted URL: {url}",
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
                f"Extracted domain: {domain}"
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
                f"Extracted email address: "
                f"{address}"
            ),
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
            builder.add(
                "file_finding",
                "file_detector",
                finding,
                confidence=(
                    finding.get(
                        "confidence",
                        100,
                    )
                    / 100
                ),
                artifact_id=artifact_id,
                summary=(
                    "Static file finding: "
                    f"{finding['attack_type']} — "
                    f"{detail}"
                ),
            )

        for error in file_analysis.get(
            "analysis_errors",
            [],
        ):
            builder.add(
                "analysis_limitation",
                "file_detector",
                error,
                artifact_id=artifact_id,
                summary=(
                    "File analysis limitation: "
                    f"{error}"
                ),
            )

        qr = file_analysis.get(
            "qr",
            {},
        )

        for payload in qr.get(
            "payloads",
            [],
        ):
            builder.add(
                "qr_payload",
                "qr_detector",
                payload,
                artifact_id=artifact_id,
                summary=(
                    "QR payload decoded from "
                    f"{payload['source']}: "
                    f"{payload['payload']}"
                ),
            )

        if qr.get("status") in {
            "error",
            "unavailable",
        }:
            reason = qr.get(
                "reason",
                "QR analysis unavailable.",
            )
            builder.add(
                "analysis_limitation",
                "qr_detector",
                reason,
                artifact_id=artifact_id,
                summary=(
                    f"QR analysis limitation: "
                    f"{reason}"
                ),
            )

    for result in url_analysis:
        url = result.get(
            "normalized_url"
        ) or result.get("url")

        for finding in result.get(
            "findings",
            [],
        ):
            builder.add(
                "url_finding",
                "url_detector",
                {
                    "url": url,
                    **finding,
                },
                confidence=(
                    0.95
                    if finding.get("type")
                    == "suspicious"
                    else 0.8
                ),
                summary=finding[
                    "message"
                ],
            )

        redirect = result.get(
            "redirect_analysis",
            {},
        )

        for hop_index, hop in enumerate(
            redirect.get(
                "hops",
                [],
            ),
            start=1,
        ):
            builder.add(
                "redirect_hop",
                "ssrf_redirect",
                {
                    "hop": hop_index,
                    **hop,
                },
                summary=(
                    f"Redirect hop {hop_index}: "
                    f"{hop.get('url')} "
                    f"returned "
                    f"{hop.get('status_code')}"
                ),
            )

        status = redirect.get(
            "status"
        )

        if status == "blocked":
            reason = redirect.get(
                "reason",
                "Unsafe redirect target.",
            )
            builder.add(
                "redirect_status",
                "ssrf_redirect",
                {
                    "status": status,
                    "reason": reason,
                    "url": url,
                },
                summary=(
                    "Redirect safety: blocked — "
                    f"{reason}"
                ),
            )
        elif redirect.get(
            "redirect_count",
            0,
        ):
            builder.add(
                "redirect_chain",
                "ssrf_redirect",
                {
                    "url": url,
                    "redirect_count": redirect[
                        "redirect_count"
                    ],
                    "status": status,
                },
                summary=(
                    "Redirect chain followed "
                    "safely: "
                    f"{redirect['redirect_count']} "
                    "redirect(s)"
                ),
            )

    if email_analysis:
        sender = email_analysis.get(
            "sender_address"
        )

        if sender:
            builder.add(
                "email_sender",
                "email_parser",
                {
                    "claimed_name": (
                        email_analysis.get(
                            "claimed_sender_name"
                        )
                    ),
                    "address": sender,
                    "domain": (
                        email_analysis.get(
                            "sender_domain"
                        )
                    ),
                },
                summary=(
                    f"Claimed sender address: "
                    f"{sender}"
                ),
            )

        for field in (
            "reply_to",
            "return_path",
            "claimed_send_time",
            "earliest_received_time",
            "originating_ip",
        ):
            value = email_analysis.get(
                field
            )

            if value:
                builder.add(
                    f"email_{field}",
                    "email_parser",
                    value,
                )

        authentication = (
            email_analysis.get(
                "authentication",
                {},
            )
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
                builder.add(
                    "email_authentication",
                    "email_parser",
                    {
                        "mechanism": mechanism,
                        "status": status,
                        "independently_verified": (
                            authentication.get(
                                "independently_verified",
                                False,
                            )
                        ),
                    },
                    summary=(
                        "Header-reported "
                        f"{mechanism.upper()}: "
                        f"{status}"
                    ),
                )

        for warning in email_analysis.get(
            "warnings",
            [],
        ):
            builder.add(
                "email_warning",
                "email_parser",
                warning,
                confidence=0.9,
                summary=(
                    "Email header indicator: "
                    f"{warning}"
                ),
            )

        routing = email_analysis.get(
            "routing_intelligence",
            {},
        )

        if routing:
            builder.add(
                "routing_intelligence",
                "virustotal",
                routing,
                summary=(
                    "Routing intelligence status: "
                    f"{routing.get('status', 'unknown')}"
                ),
            )

    for result in threat_intelligence:
        domain = result.get(
            "domain",
            "unknown",
        )
        status = result.get(
            "status",
            "unknown",
        )

        if status == "success":
            summary = (
                "VirusTotal: "
                f"{result.get('malicious', 0)} "
                "malicious, "
                f"{result.get('suspicious', 0)} "
                "suspicious detections for "
                f"{domain}"
            )
        else:
            summary = (
                "VirusTotal: "
                f"{result.get('message', status)} "
                f"for {domain}"
            )

        builder.add(
            "threat_intelligence",
            "virustotal",
            result,
            summary=summary,
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

        if summary and summary not in summaries:
            summaries.append(summary)

    return summaries

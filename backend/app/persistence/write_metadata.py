from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)

from psycopg.types.json import Jsonb


def parse_timestamp(
    value: str | datetime | None,
) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif not value:
        return None
    else:
        try:
            parsed = datetime.fromisoformat(
                str(value).replace(
                    "Z",
                    "+00:00",
                )
            )
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed


def insert_artifact(
    connection,
    investigation_id: int,
    file_info: dict | None,
    *,
    artifact_key: str | None = "artifact-1",
) -> None:
    if not file_info:
        return

    connection.execute(
        """
        INSERT INTO artifacts (
            investigation_id,
            artifact_key,
            filename,
            extension,
            declared_mime,
            detected_type,
            size_bytes,
            sha256,
            parser,
            characters_extracted,
            truncated,
            metadata
        )
        VALUES (
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (
            investigation_id,
            artifact_key
        )
        DO NOTHING
        """,
        (
            investigation_id,
            artifact_key,
            file_info.get("filename"),
            file_info.get("extension"),
            file_info.get("declared_mime"),
            file_info.get("detected_type"),
            file_info.get("size_bytes"),
            file_info.get("sha256"),
            file_info.get("parser"),
            file_info.get(
                "characters_extracted"
            ),
            bool(
                file_info.get(
                    "truncated",
                    False,
                )
            ),
            Jsonb(file_info),
        ),
    )


def insert_derived_artifacts(
    connection,
    investigation_id: int,
    evidence_items: list[dict],
) -> None:
    for item in evidence_items:
        if (
            item.get("type") != "artifact"
            or item.get("source")
            != "email_attachment"
        ):
            continue

        value = item.get("value")

        if not isinstance(value, dict):
            continue

        insert_artifact(
            connection,
            investigation_id,
            value,
            artifact_key=item.get(
                "artifact_id"
            ),
        )


def insert_email(
    connection,
    investigation_id: int,
    email_analysis: dict | None,
) -> None:
    if not email_analysis:
        return

    routing = email_analysis.get(
        "routing_intelligence",
        {},
    )

    connection.execute(
        """
        INSERT INTO email_metadata (
            investigation_id,
            claimed_sender_name,
            sender_address,
            sender_domain,
            reply_to,
            return_path,
            subject,
            message_id,
            claimed_send_time,
            earliest_received_time,
            originating_ip,
            routing_country,
            routing_asn,
            routing_owner,
            authentication,
            warnings,
            attachments,
            raw_metadata
        )
        VALUES (
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s
        )
        """,
        (
            investigation_id,
            email_analysis.get(
                "claimed_sender_name"
            ),
            email_analysis.get(
                "sender_address"
            ),
            email_analysis.get(
                "sender_domain"
            ),
            email_analysis.get("reply_to"),
            email_analysis.get(
                "return_path"
            ),
            email_analysis.get("subject"),
            email_analysis.get(
                "message_id"
            ),
            parse_timestamp(
                email_analysis.get(
                    "claimed_send_time"
                )
            ),
            parse_timestamp(
                email_analysis.get(
                    "earliest_received_time"
                )
            ),
            email_analysis.get(
                "originating_ip"
            ),
            routing.get("country"),
            routing.get("asn"),
            routing.get("as_owner"),
            Jsonb(
                email_analysis.get(
                    "authentication",
                    {},
                )
            ),
            Jsonb(
                email_analysis.get(
                    "warnings",
                    [],
                )
            ),
            Jsonb(
                email_analysis.get(
                    "attachments",
                    [],
                )
            ),
            Jsonb(email_analysis),
        ),
    )


def insert_redirects(
    connection,
    investigation_id: int,
    url_analysis: list[dict],
) -> None:
    for result in url_analysis:
        original_url = (
            result.get("url")
            or result.get(
                "normalized_url"
            )
            or ""
        )
        redirect = result.get(
            "redirect_analysis",
            {},
        )
        hops = redirect.get(
            "hops",
            [],
        )

        for index, hop in enumerate(
            hops,
            start=1,
        ):
            connection.execute(
                """
                INSERT INTO redirect_hops (
                    investigation_id,
                    original_url,
                    hop_order,
                    url,
                    resolved_ips,
                    status_code,
                    method,
                    blocked_reason,
                    is_final
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    investigation_id,
                    original_url,
                    index,
                    hop.get(
                        "url",
                        original_url,
                    ),
                    Jsonb(
                        hop.get(
                            "resolved_ips",
                            [],
                        )
                    ),
                    hop.get("status_code"),
                    hop.get("method"),
                    (
                        redirect.get("reason")
                        if (
                            index
                            == len(hops)
                            and redirect.get(
                                "status"
                            )
                            == "blocked"
                        )
                        else None
                    ),
                    (
                        index == len(hops)
                        and redirect.get(
                            "status"
                        )
                        == "completed"
                    ),
                ),
            )

        if (
            not hops
            and redirect.get(
                "status"
            )
            == "blocked"
        ):
            connection.execute(
                """
                INSERT INTO redirect_hops (
                    investigation_id,
                    original_url,
                    hop_order,
                    url,
                    blocked_reason,
                    is_final
                )
                VALUES (
                    %s, %s, 0, %s, %s, TRUE
                )
                """,
                (
                    investigation_id,
                    original_url,
                    redirect.get(
                        "blocked_url",
                        original_url,
                    ),
                    redirect.get("reason"),
                ),
            )

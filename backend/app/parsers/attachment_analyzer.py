from __future__ import annotations

from pathlib import Path
from typing import Callable

MAX_EMAIL_ATTACHMENTS = 20
MAX_NESTED_DEPTH = 2


def analyze_email_attachments(
    payloads: list[dict],
    metadata: list[dict],
    *,
    depth: int,
    read_file: Callable,
) -> tuple[list[dict], list[str]]:
    nested = []
    extracted_text = []

    for index, item in enumerate(
        payloads[:MAX_EMAIL_ATTACHMENTS]
    ):
        filename = (
            item.get("filename")
            or f"attachment-{index + 1}"
        )
        content_type = item.get(
            "content_type"
        )
        data = item.get("data") or b""

        target = (
            metadata[index]
            if index < len(metadata)
            else None
        )

        if depth >= MAX_NESTED_DEPTH:
            if target is not None:
                target[
                    "analysis_status"
                ] = "depth_limit"
            continue

        if not Path(filename).suffix:
            if target is not None:
                target[
                    "analysis_status"
                ] = "unsupported"
            continue

        try:
            child = read_file(
                filename,
                content_type,
                data,
                depth + 1,
            )
        except Exception as exc:
            status = getattr(
                exc,
                "status_code",
                None,
            )

            if target is not None:
                target[
                    "analysis_status"
                ] = (
                    "unsupported"
                    if status == 415
                    else "unavailable"
                )
            continue

        if target is not None:
            target[
                "analysis_status"
            ] = "analyzed"
            target["sha256"] = child[
                "file_info"
            ]["sha256"]

        nested.append(
            {
                "filename": filename,
                "file_info": child[
                    "file_info"
                ],
                "file_analysis": child[
                    "file_analysis"
                ],
                "email_analysis": child.get(
                    "email_analysis"
                ),
            }
        )

        if child.get("content"):
            extracted_text.append(
                child["content"]
            )

    if len(payloads) > MAX_EMAIL_ATTACHMENTS:
        for item in metadata[
            MAX_EMAIL_ATTACHMENTS:
        ]:
            item[
                "analysis_status"
            ] = "attachment_limit"

    return nested, extracted_text

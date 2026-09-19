from __future__ import annotations

from app.models import (
    AttackChainStage,
    AttackFinding,
    EvidenceItem,
)

STAGE_ORDER = {
    "Source": 1,
    "Delivery Technique": 2,
    "Object": 3,
    "Embedded Object": 4,
    "Destination": 5,
    "URL Behavior": 6,
    "Website / Authentication Technique": 7,
    "Payload / Objective": 8,
    "Potential Impact": 9,
}


def _items(
    evidence_items: list[EvidenceItem],
    evidence_type: str,
) -> list[EvidenceItem]:
    return [
        item
        for item in evidence_items
        if item.type == evidence_type
    ]


def _finding(
    findings: list[AttackFinding],
    attack_type: str,
) -> AttackFinding | None:
    return next(
        (
            finding
            for finding in findings
            if finding.attack_type
            == attack_type
        ),
        None,
    )


def _stage(
    stage: str,
    value: str,
    confidence: int,
    evidence_ids: list[str],
) -> AttackChainStage:
    return AttackChainStage(
        order=STAGE_ORDER[stage],
        stage=stage,
        value=value,
        confidence=confidence,
        evidence_ids=list(
            dict.fromkeys(evidence_ids)
        ),
    )


def build_attack_chain(
    evidence_items: list[EvidenceItem],
    findings: list[AttackFinding],
) -> list[AttackChainStage]:
    stages: list[AttackChainStage] = []

    sender_items = _items(
        evidence_items,
        "email_sender",
    )

    if sender_items:
        sender = sender_items[0]
        address = sender.value.get(
            "address"
        )

        if address:
            stages.append(
                _stage(
                    "Source",
                    (
                        "Claimed email sender: "
                        f"{address}"
                    ),
                    100,
                    [sender.id],
                )
            )

    artifact_items = _items(
        evidence_items,
        "artifact",
    )
    artifact = (
        artifact_items[0]
        if artifact_items
        else None
    )

    qr_finding = _finding(
        findings,
        "QR Link Delivery",
    )
    url_items = _items(
        evidence_items,
        "indicator_url",
    )

    if qr_finding:
        stages.append(
            _stage(
                "Delivery Technique",
                "QR code containing an HTTP(S) link",
                qr_finding.confidence,
                qr_finding.evidence_ids,
            )
        )
    elif (
        sender_items
        and url_items
    ):
        stages.append(
            _stage(
                "Delivery Technique",
                "Email containing an HTTP(S) link",
                95,
                [
                    sender_items[0].id,
                    url_items[0].id,
                ],
            )
        )
    elif artifact:
        extension = artifact.value.get(
            "extension",
            "",
        )
        if extension == ".eml":
            stages.append(
                _stage(
                    "Delivery Technique",
                    "Email message artifact",
                    100,
                    [artifact.id],
                )
            )

    if artifact:
        filename = artifact.value.get(
            "filename"
        )

        if filename:
            stages.append(
                _stage(
                    "Object",
                    filename,
                    100,
                    [artifact.id],
                )
            )

    embedded_items = [
        item
        for item in _items(
            evidence_items,
            "file_finding",
        )
        if item.value.get(
            "attack_type"
        )
        in {
            "Embedded Object Present",
            "Embedded PDF File",
        }
    ]

    qr_items = _items(
        evidence_items,
        "qr_payload",
    )

    if qr_items:
        stages.append(
            _stage(
                "Embedded Object",
                "Decoded QR payload",
                100,
                [
                    item.id
                    for item in qr_items
                ],
            )
        )
    elif embedded_items:
        stages.append(
            _stage(
                "Embedded Object",
                embedded_items[0].value.get(
                    "attack_type",
                    "Embedded content",
                ),
                95,
                [
                    item.id
                    for item in embedded_items
                ],
            )
        )

    if url_items:
        stages.append(
            _stage(
                "Destination",
                str(
                    url_items[0].value
                ),
                100,
                [url_items[0].id],
            )
        )

    redirect_finding = _finding(
        findings,
        "Redirect Chain",
    )
    url_deception = _finding(
        findings,
        "URL Deception Indicators",
    )

    if redirect_finding:
        stages.append(
            _stage(
                "URL Behavior",
                "Observed redirect chain",
                redirect_finding.confidence,
                redirect_finding.evidence_ids,
            )
        )
    elif url_deception:
        stages.append(
            _stage(
                "URL Behavior",
                "Deceptive URL structure indicators",
                url_deception.confidence,
                url_deception.evidence_ids,
            )
        )

    password_items = [
        item
        for item in _items(
            evidence_items,
            "file_finding",
        )
        if item.value.get(
            "attack_type"
        )
        == "Password Input Form"
    ]
    credential_finding = _finding(
        findings,
        "Credential Phishing Pattern",
    )

    if password_items:
        stages.append(
            _stage(
                "Website / Authentication Technique",
                "Password input form",
                100,
                [
                    item.id
                    for item in password_items
                ],
            )
        )
    elif credential_finding:
        stages.append(
            _stage(
                "Website / Authentication Technique",
                "Credential collection request",
                credential_finding.confidence,
                credential_finding.evidence_ids,
            )
        )

    objective_candidates = (
        (
            "MFA Theft Pattern",
            "MFA verification-code collection",
        ),
        (
            "Credential Phishing Pattern",
            "Credential collection",
        ),
        (
            "Payment Diversion Pattern",
            "Payment or banking-detail change",
        ),
        (
            "Executable or Script in Archive",
            "Executable or script delivery",
        ),
    )

    selected_objective = None

    for attack_type, value in (
        objective_candidates
    ):
        selected_objective = _finding(
            findings,
            attack_type,
        )

        if selected_objective:
            stages.append(
                _stage(
                    "Payload / Objective",
                    value,
                    selected_objective.confidence,
                    selected_objective.evidence_ids,
                )
            )
            break

    impact_candidates = (
        (
            "MFA Theft Pattern",
            "Potential MFA code compromise",
        ),
        (
            "Credential Phishing Pattern",
            "Potential credential disclosure",
        ),
        (
            "Payment Diversion Pattern",
            "Potential payment diversion",
        ),
    )

    for attack_type, value in impact_candidates:
        finding = _finding(
            findings,
            attack_type,
        )

        if finding:
            stages.append(
                _stage(
                    "Potential Impact",
                    value,
                    min(
                        finding.confidence,
                        85,
                    ),
                    finding.evidence_ids,
                )
            )
            break

    return sorted(
        stages,
        key=lambda stage: stage.order,
    )


def chain_as_dicts(
    stages: list[AttackChainStage],
) -> list[dict]:
    return [
        stage.model_dump()
        for stage in stages
    ]

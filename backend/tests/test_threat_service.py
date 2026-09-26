from app.services import threat_service


def test_uses_ip_intelligence_for_ip_hosts(
    monkeypatch,
):
    monkeypatch.setattr(
        threat_service,
        "check_ip",
        lambda value: {
            "ip": value,
            "status": "success",
        },
    )
    monkeypatch.setattr(
        threat_service,
        "check_domain",
        lambda value: {
            "domain": value,
            "status": "success",
        },
    )

    results = (
        threat_service
        .gather_threat_intelligence(
            {
                "domains": [
                    "8.8.8.8",
                    "example.test",
                ]
            }
        )
    )

    assert results[0]["ip"] == "8.8.8.8"
    assert (
        results[1]["domain"]
        == "example.test"
    )


def test_adds_file_hash_intelligence(
    monkeypatch,
):
    monkeypatch.setattr(
        threat_service,
        "check_hash",
        lambda value: {
            "hash": value,
            "status": "unknown",
        },
    )

    results = (
        threat_service
        .gather_threat_intelligence(
            {"domains": []},
            {"sha256": "a" * 64},
        )
    )

    assert results == [
        {
            "hash": "a" * 64,
            "status": "unknown",
        }
    ]

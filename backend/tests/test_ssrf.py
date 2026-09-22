from app.security import ssrf


def test_blocks_loopback_target():
    result = ssrf.safe_follow(
        "http://127.0.0.1/"
    )

    assert result["status"] == "blocked"
    assert result["hops"] == []
    assert result["blocked_url"] == (
        "http://127.0.0.1/"
    )


def test_blocks_cloud_metadata_target():
    result = ssrf.safe_follow(
        "http://169.254.169.254/latest/meta-data/"
    )

    assert result["status"] == "blocked"


def test_blocks_non_http_scheme():
    result = ssrf.safe_follow(
        "file:///etc/passwd"
    )

    assert result["status"] == "blocked"


def test_revalidates_every_redirect_hop(monkeypatch):
    def fake_resolve(hostname, port):
        if hostname == "public.test":
            return ["93.184.216.34"]

        return ["127.0.0.1"]

    def fake_request(url, addresses):
        assert addresses == [
            "93.184.216.34"
        ]
        return {
            "status_code": 302,
            "location": (
                "http://internal.test/admin"
            ),
            "method": "HEAD",
        }

    monkeypatch.setattr(
        ssrf,
        "_resolve_ips",
        fake_resolve,
    )
    monkeypatch.setattr(
        ssrf,
        "_request_once",
        fake_request,
    )

    result = ssrf.safe_follow(
        "https://public.test/"
    )

    assert result["status"] == "blocked"
    assert len(result["hops"]) == 1


def test_returns_completed_for_public_non_redirect(
    monkeypatch,
):
    monkeypatch.setattr(
        ssrf,
        "_resolve_ips",
        lambda hostname, port: [
            "93.184.216.34"
        ],
    )
    monkeypatch.setattr(
        ssrf,
        "_request_once",
        lambda url, addresses: {
            "status_code": 200,
            "location": None,
            "method": "HEAD",
        },
    )

    result = ssrf.safe_follow(
        "https://public.test/path"
    )

    assert result["status"] == "completed"
    assert result["redirect_count"] == 0
    assert (
        result["hops"][0]["method"]
        == "HEAD"
    )

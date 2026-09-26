from app.tools.url_analysis import analyze_url
from app.tools.url_utils import (
    normalize_http_url,
)


def _messages(result):
    return [
        finding["message"]
        for finding in result["findings"]
    ]


def test_registered_domain_and_subdomain_are_extracted():
    result = analyze_url(
        "https://a.b.example.com/login"
    )

    assert result["registered_domain"] == "example.com"
    assert result["subdomain"] == "a.b"


def test_detects_punycode_and_many_subdomains():
    result = analyze_url(
        "https://a.b.c.xn--e1awd7f.com/"
    )
    messages = _messages(result)

    assert "Domain uses Punycode" in messages
    assert (
        "Domain contains many subdomain levels"
        in messages
    )


def test_detects_non_standard_port():
    result = analyze_url(
        "https://example.com:8443/login"
    )

    assert any(
        "non-standard port" in message
        for message in _messages(result)
    )


def test_detects_encoded_deception():
    result = analyze_url(
        "https://example.com/%2540/%2f"
    )
    messages = _messages(result)

    assert (
        "URL contains possible double encoding"
        in messages
    )
    assert any(
        "percent-encoded" in message
        for message in messages
    )


def test_detects_domain_like_name_in_subdomain():
    result = analyze_url(
        "https://login.example.com.attacker.net/"
    )

    assert any(
        "Subdomain contains the domain-like name"
        in message
        for message in _messages(result)
    )


def test_detects_possible_typosquat_pattern():
    result = analyze_url(
        "https://paypa1-login.com/"
    )

    assert any(
        "possible typosquat" in message
        for message in _messages(result)
    )


def test_ip_host_does_not_create_registered_domain():
    result = analyze_url(
        "http://8.8.8.8/"
    )

    assert result["registered_domain"] == ""
    assert any(
        "IP address" in message
        for message in _messages(result)
    )



def test_normalizes_unicode_hostname_to_idna():
    normalized, hostname = (
        normalize_http_url(
            "https://täst.example/path"
        )
    )

    assert hostname == (
        "xn--tst-qla.example"
    )
    assert (
        "xn--tst-qla.example"
        in normalized
    )

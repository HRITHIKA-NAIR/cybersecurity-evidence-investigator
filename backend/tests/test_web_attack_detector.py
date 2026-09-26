from app.detectors.web_attack_detector import (
    detect_web_attack_indicators,
)


def _types(content):
    return {
        item["attack_type"]
        for item in (
            detect_web_attack_indicators(
                content
            )
        )
    }


def test_detects_submitted_sqli_and_xss_evidence():
    types = _types(
        "' OR 1=1 -- <script>alert(1)</script>"
    )

    assert (
        "SQL Injection Indicator"
        in types
    )
    assert "XSS Indicator" in types


def test_benign_text_has_no_web_attack_finding():
    assert (
        detect_web_attack_indicators(
            "Quarterly meeting notes."
        )
        == []
    )

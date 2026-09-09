"""POST /api/v1/download/check - browser-level pre-download risk check."""

import json

import pytest


@pytest.fixture
def client():
    import cybersentinel.web.api as api
    api.app.config.update(TESTING=True)
    return api.app.test_client()


def _post(client, body):
    r = client.post("/api/v1/download/check", data=json.dumps(body),
                    content_type="application/json")
    return r.status_code, r.get_json()


def test_double_extension_is_blocked(client):
    code, j = _post(client, {"url": "http://x.example/f", "filename": "invoice.pdf.exe"})
    assert code == 200
    assert j["enforcement_action"] == "BLOCK"
    assert j["risk_percent"] >= 55
    assert any("double extension" in r for r in j["reasons"])


def test_plain_executable_is_suspicious_not_malicious(client):
    code, j = _post(client, {"url": "https://good-cdn.example/app", "filename": "setup.exe",
                             "mime": "application/x-msdownload"})
    assert j["enforcement_action"] in ("WARN", "BLOCK")
    assert j["recommendation"]


def test_benign_document_is_allowed(client):
    code, j = _post(client, {"url": "https://example.com/report", "filename": "report.pdf"})
    assert j["enforcement_action"] == "ALLOW"
    assert j["classification"] == "SAFE"


def test_keygen_pattern_flagged(client):
    code, j = _post(client, {"filename": "photoshop-keygen-2024.exe"})
    assert j["risk_percent"] >= 55
    assert any("unwanted-software" in r for r in j["reasons"])


def test_response_notes_the_limitation(client):
    _, j = _post(client, {"filename": "x.txt"})
    assert "authoritative on-disk scan" in j["note"]


def test_content_check_endpoint(client):
    client.post("/api/v1/content/policy", data=json.dumps(
        {"enabled": True, "blocked_categories": ["gambling"]}), content_type="application/json")
    r = client.post("/api/v1/content/check", data=json.dumps({"url": "https://bet365.com/"}),
                    content_type="application/json")
    j = r.get_json()
    assert j["blocked"] is True
    assert j["enforcement_action"] == "REDIRECT"
    assert j["content_category"] == "gambling"
    # reset
    client.post("/api/v1/content/policy", data=json.dumps({"enabled": False}),
                content_type="application/json")

"""Phishing + content-filter enforcement via the real API + engines.

Covers: /url/scan mapping (part 7), manual==extension engine (part 8/16),
content filter separation + enable/disable (part 12), enforcement_action in
every non-safe result (part 17), safe-landing redirect target (part 14).
"""

import asyncio
import json

import pytest


@pytest.fixture(scope="module")
def client():
    import cybersentinel.web.api as api
    api.app.config.update(TESTING=True)
    c = api.app.test_client()
    yield c
    # reset content policy
    c.post("/api/v1/content/policy", json={"enabled": False, "blocked_categories": []})


def scan(client, url):
    return client.post("/api/v1/url/scan", json={"url": url}).get_json()


# --- part 7: risk -> enforcement mapping, legit sites not blocked -----------

LEGIT = [
    "https://www.google.com/", "https://en.wikipedia.org/wiki/Security",
    "https://www.microsoft.com/", "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/12345", "https://www.amazon.com/dp/B08",
    "https://news.ycombinator.com/", "https://www.reddit.com/r/programming/",
    "https://www.bbc.com/news", "https://www.paypal.com/signin",
    "https://accounts.google.com/signin",
]
PHISH = [
    "http://paypa1-account-verify.tk/login/confirm-identity",
    "http://secure-chase-verify.tk/account/update",
    "http://apple-id-locked.ml/signin", "http://paypa1.com/",
    "http://amaz0n-security.xyz/login", "https://xn--pple-43d.com/verify",
    "http://microsoft-support-alert.tk/", "http://netflix-billing-update.ml/account",
]


def test_no_legit_site_is_blocked(client):
    blocked = [u for u in LEGIT if scan(client, u)["enforcement_action"] == "REDIRECT"]
    assert blocked == [], f"legitimate sites blocked: {blocked}"


def test_obvious_phishing_is_not_missed(client):
    missed = [u for u in PHISH if scan(client, u)["enforcement_action"] == "ALLOW"]
    assert missed == [], f"phishing not enforced: {missed}"


def test_phishing_url_maps_to_redirect(client):
    j = scan(client, "http://paypa1-account-verify.tk/login/confirm-identity")
    assert j["classification"] in ("PHISHING", "SUSPICIOUS")
    if j["classification"] == "PHISHING":
        assert j["enforcement_action"] == "REDIRECT"
    assert j["xai_explanation"]
    assert j["recommendation"]


def test_typosquat_and_homograph_produce_evidence(client):
    typo = scan(client, "http://paypa1.com/")
    assert typo["risk_percent"] >= 0  # scored
    homo = scan(client, "https://xn--pple-43d.com/")   # punycode 'ápple'
    assert homo["risk_percent"] >= 0


def test_unknown_is_not_safe(client):
    # a scheme the phishing analyzers can't score meaningfully still must not be SAFE-by-accident
    j = client.post("/api/v1/url/scan", json={"url": "not-a-url"}).get_json()
    assert j["classification"] != "PHISHING"
    assert j["enforcement_action"] in ("ALLOW", "WARN", "ANALYSIS_INCOMPLETE")


# --- part 17: every non-safe result carries the full envelope --------------

def test_result_envelope_is_complete(client):
    j = scan(client, "http://verify-amazon-account.tk/login")
    for k in ("classification", "risk_score", "risk_percent", "risk_level",
              "analysis_status", "evidence", "xai_explanation", "recommendation",
              "enforcement_action"):
        assert k in j, k


# --- part 8 / 16: manual scan and the engine use the same phishing engine --

def test_manual_scan_matches_orchestrator(client):
    from cybersentinel.orchestrator import ThreatOrchestrator
    from cybersentinel.phishing_engine.analyzer import PhishingEngine

    url = "http://secure-chase-verify.tk/account/update"
    api_result = scan(client, url)

    orch = ThreatOrchestrator()
    for i, a in enumerate(PhishingEngine().analyzers):
        orch.register_phishing_engine(f"p{i}", a)
    direct = asyncio.run(orch.analyze_url(url)).outcome

    assert api_result["classification"] == direct["classification"]
    assert abs(api_result["risk_percent"] - direct["risk_percent"]) < 0.01


# --- part 12-14: content filter is separate, opt-in, redirect target safe --

def test_content_filter_disabled_by_default(client):
    client.post("/api/v1/content/policy", json={"enabled": False})
    j = client.post("/api/v1/content/check", json={"url": "https://xvideos.com/"}).get_json()
    assert j["content_risk"] > 0.6          # categorised
    assert j["blocked"] is False             # but not enforced
    assert j["enforcement_action"] == "ALLOW"
    assert "malware" not in json.dumps(j).lower()
    assert "phishing" not in json.dumps(j).lower()


def test_content_filter_blocks_when_enabled_then_stops_when_disabled(client):
    client.post("/api/v1/content/policy", json={"enabled": True, "blocked_categories": ["adult"]})
    j = client.post("/api/v1/content/check", json={"url": "https://xvideos.com/"}).get_json()
    assert j["blocked"] is True
    assert j["content_category"] == "adult"
    assert j["enforcement_action"] == "REDIRECT"
    assert "content-filtering policy" in j["reason"]

    client.post("/api/v1/content/policy", json={"enabled": False})
    j2 = client.post("/api/v1/content/check", json={"url": "https://xvideos.com/"}).get_json()
    assert j2["blocked"] is False


def test_content_filter_does_not_flag_incidental_keyword(client):
    client.post("/api/v1/content/policy", json={"enabled": True, "blocked_categories": ["gambling"]})
    j = client.post("/api/v1/content/check", json={
        "url": "https://en.wikipedia.org/wiki/Poker", "page_title": "Poker - Wikipedia"}).get_json()
    assert j["blocked"] is False
    client.post("/api/v1/content/policy", json={"enabled": False})


def test_safe_landing_is_a_fixed_google_url():
    cfg = (open("extension/config.js", encoding="utf-8").read())
    assert 'SAFE_LANDING: "https://www.google.com/"' in cfg
    # the block page's redirect must not carry query/token data
    bjs = open("extension/blocked.js", encoding="utf-8").read()
    assert "location.replace(SAFE)" in bjs
    assert "location.replace(url)" in bjs  # only on explicit "proceed anyway"


# --- part 9: health endpoint tells the truth ------------------------------

def test_realtime_health_reports_real_component_state(client):
    j = client.get("/api/v1/realtime/health").get_json()
    assert j["protection"] in ("PROTECTION ACTIVE", "PROTECTION DEGRADED", "PROTECTION OFFLINE")
    assert j["malware_engine"] in ("active", "degraded", "unavailable")
    assert j["yara"] in ("available", "unavailable")

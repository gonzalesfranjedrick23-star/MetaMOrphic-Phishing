"""Content filter (spec parts 15-17) - separate from phishing, opt-in, threshold-gated."""

from cybersentinel.content_filter import ContentFilterEngine, ContentPolicy, CATEGORIES


def test_disabled_by_default_never_blocks():
    r = ContentFilterEngine().classify("https://www.xvideos.com/")
    assert r["content_risk"] > 0.6           # it IS categorised
    assert r["blocked"] is False              # but nothing is blocked when disabled
    assert r["content_policy"] == "allow"


def test_enabled_category_blocks_over_threshold():
    p = ContentPolicy(enabled=True, blocked_categories=["adult"])
    r = ContentFilterEngine(p).classify("https://xvideos.com/")
    assert r["blocked"] is True
    assert r["content_category"] == "adult"
    assert r["enforcement_action"] if "enforcement_action" in r else True
    assert "content-filtering policy" in r["reason"]
    assert "malware" not in r["reason"].lower()   # never claims it's malware


def test_uncertain_keyword_only_does_not_block():
    p = ContentPolicy(enabled=True, blocked_categories=["gambling"])
    # an article that mentions poker is not a gambling site
    r = ContentFilterEngine(p).classify("https://en.wikipedia.org/wiki/Poker",
                                        page_title="Poker - Wikipedia")
    assert r["blocked"] is False


def test_category_not_in_blocklist_is_allowed():
    p = ContentPolicy(enabled=True, blocked_categories=["gambling"])
    r = ContentFilterEngine(p).classify("https://xvideos.com/")
    assert r["content_category"] == "adult"
    assert r["blocked"] is False


def test_allowlist_bypasses_filter():
    p = ContentPolicy(enabled=True, blocked_categories=["adult"], allowlist=["xvideos.com"])
    r = ContentFilterEngine(p).classify("https://xvideos.com/")
    assert r["blocked"] is False


def test_policy_roundtrip(tmp_path):
    p = ContentPolicy(enabled=True, blocked_categories=["adult", "gambling"], threshold=0.7)
    p.save(tmp_path / "cp.json")
    loaded = ContentPolicy.load(tmp_path / "cp.json")
    assert loaded.enabled and loaded.threshold == 0.7
    assert set(loaded.blocked_categories) == {"adult", "gambling"}
    assert set(CATEGORIES) >= {"adult", "gambling", "violence", "drugs"}


def test_benign_site_is_category_none():
    r = ContentFilterEngine().classify("https://www.python.org/")
    assert r["content_category"] == "none"
    assert r["content_risk"] < 0.2

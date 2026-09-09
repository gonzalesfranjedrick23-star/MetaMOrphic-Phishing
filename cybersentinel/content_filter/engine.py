"""Content-filter classifier: URL / domain / page-signal based category matching.

Evidence-based and threshold-gated (spec part 33 - "content category uncertainty
!= definite violation"). The user chooses which categories to block; nothing is
blocked unless its category is enabled AND the risk clears the threshold.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

CATEGORIES = ["adult", "gambling", "violence", "drugs", "hate", "malware_hosting"]

# Conservative keyword signals per category. These are lexical hints only - the
# score also needs corroboration (domain token OR multiple hits) before blocking.
_KEYWORDS: Dict[str, List[str]] = {
    "adult": ["porn", "xxx", "nsfw", "camgirl", "hentai", "escort", "adultfriend", "onlyfans"],
    "gambling": ["casino", "betting", "sportsbook", "poker", "slots", "roulette", "wager", "bookmaker"],
    "violence": ["gore", "beheading", "liveleak", "snuff"],
    "drugs": ["buy-weed", "darknetmarket", "cocaine", "mdma", "psychedelics-shop", "research-chemicals"],
    "hate": ["whitepower", "1488"],
    "malware_hosting": ["keygen", "crack-download", "warez", "nulled", "serial-key"],
}

# High-confidence domain tokens (substring of the registrable domain).
_DOMAIN_TOKENS: Dict[str, List[str]] = {
    "adult": ["porn", "xxx", "xvideos", "xnxx", "redtube", "youporn", "brazzers", "adult"],
    "gambling": ["casino", "bet365", "pokerstars", "draftkings", "fanduel", "betway", "bovada"],
    "violence": ["bestgore", "documentingreality"],
    "drugs": ["silkroad", "dreammarket"],
    "hate": ["stormfront"],
    "malware_hosting": ["thepiratebay", "1337x", "nulled", "cracked.to"],
}

DEFAULT_THRESHOLD = 0.6


@dataclass
class ContentPolicy:
    enabled: bool = False
    blocked_categories: List[str] = field(default_factory=list)
    threshold: float = DEFAULT_THRESHOLD
    allowlist: List[str] = field(default_factory=list)   # hostnames never filtered

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "ContentPolicy":
        d = d or {}
        cats = [c for c in d.get("blocked_categories", []) if c in CATEGORIES]
        return cls(
            enabled=bool(d.get("enabled", False)),
            blocked_categories=cats,
            threshold=float(d.get("threshold", DEFAULT_THRESHOLD)),
            allowlist=[h.lower() for h in d.get("allowlist", [])],
        )

    @classmethod
    def load(cls, path: str | Path) -> "ContentPolicy":
        try:
            return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return cls()

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


class ContentFilterEngine:
    def __init__(self, policy: Optional[ContentPolicy] = None):
        self.policy = policy or ContentPolicy()

    def classify(self, url: str, page_title: str = "", page_text_sample: str = "") -> Dict[str, Any]:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        reg = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        haystack = " ".join([url.lower(), page_title.lower(), page_text_sample.lower()[:2000]])

        scores: Dict[str, float] = {c: 0.0 for c in CATEGORIES}
        matched: Dict[str, List[str]] = {c: [] for c in CATEGORIES}

        for cat, tokens in _DOMAIN_TOKENS.items():
            for tok in tokens:
                if tok in reg or tok in host:
                    scores[cat] = max(scores[cat], 0.85)
                    matched[cat].append(f"domain token '{tok}'")
        for cat, words in _KEYWORDS.items():
            hits = [w for w in words if w in haystack]
            if hits:
                # keyword hits alone are weak; strong only with 2+ or a domain token
                base = 0.35 + 0.15 * min(len(hits), 3)
                if matched[cat]:
                    base = max(base, 0.8)
                scores[cat] = max(scores[cat], min(base, 0.9))
                matched[cat].extend(f"keyword '{w}'" for w in hits)

        category = max(scores, key=lambda c: scores[c])
        risk = round(scores[category], 3)
        if risk < 0.2:
            category = "none"

        blocked = False
        policy_state = "allow"
        reason = "No content-policy match."
        recommendation = ""
        if self.policy.enabled and host and host not in self.policy.allowlist:
            if category in self.policy.blocked_categories and risk >= self.policy.threshold:
                blocked = True
                policy_state = "block"
                reason = (f"This website was blocked by the enabled content-filtering "
                          f"policy (category: {category}, confidence {risk:.0%}).")
                recommendation = ("Return to a safer search page, or disable this "
                                  "category in Protection Settings.")

        return {
            "content_category": category,
            "content_risk": risk,
            "content_policy": policy_state,
            "blocked": blocked,
            "matched": matched.get(category, []) if category != "none" else [],
            "all_scores": {c: round(s, 3) for c, s in scores.items() if s > 0},
            "reason": reason,
            "recommendation": recommendation,
            "policy": {
                "enabled": self.policy.enabled,
                "blocked_categories": self.policy.blocked_categories,
                "threshold": self.policy.threshold,
            },
        }

"""Optional content-filtering policy (spec parts 15-17).

Kept deliberately separate from phishing detection: an inappropriate website is
NOT malware and NOT necessarily phishing. Produces its own result shape:

    {
        "content_category": "adult" | "gambling" | ... | "none",
        "content_risk": 0.0-1.0,
        "content_policy": "allow" | "block",
        "blocked": bool,
        "matched": [ ... evidence ... ],
        "reason": str,
        "recommendation": str,
    }
"""

from .engine import ContentFilterEngine, ContentPolicy, CATEGORIES

__all__ = ["ContentFilterEngine", "ContentPolicy", "CATEGORIES"]

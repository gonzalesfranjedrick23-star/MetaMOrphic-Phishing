"""
Phishing Detection Engine

Integrates multiple phishing analyzers:
- KNN model (existing JavaScript model, 89.4% accuracy)
- URL feature analysis
- Domain lookalike detection
- [Future] HTML/DOM analysis
- [Future] JavaScript static analysis
- [Future] NLP analysis
- [Future] Visual/OCR analysis
"""

from .analyzer import (
    PhishingEngine,
    PhishingAnalyzer,
    KNNPhishingAnalyzer,
    URLFeatureAnalyzer,
    DomainLookalikeAnalyzer,
)

__all__ = [
    "PhishingEngine",
    "PhishingAnalyzer",
    "KNNPhishingAnalyzer",
    "URLFeatureAnalyzer",
    "DomainLookalikeAnalyzer",
]

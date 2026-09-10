"""
Phishing Detection Engine: Unified interface for phishing threat detection.

Integrates the existing JavaScript KNN model with new analysis layers:
- URL feature extraction
- Domain analysis (lookalike detection)
- HTML/DOM analysis
- JavaScript static analysis
- NLP-based content analysis
- Visual/screenshot analysis
- Infrastructure analysis
"""

import asyncio
import json
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
import logging
from pathlib import Path

from cybersentinel.common import ModelPrediction


logger = logging.getLogger(__name__)


class PhishingAnalyzer(ABC):
    """Base class for phishing analyzers."""
    
    @abstractmethod
    async def analyze(self, url: str) -> Optional[ModelPrediction]:
        """Analyze a URL for phishing indicators."""
        pass


class KNNPhishingAnalyzer(PhishingAnalyzer):
    """
    KNN-based phishing detector (existing JavaScript model).
    
    Integrates the pure JavaScript KNN model from the extension.
    Model file: saved_models/seed_model.json
    
    Features:
    - length_url
    - length_hostname
    - nb_dots
    - nb_hyphens
    - nb_qm
    - nb_eq
    - nb_slash
    - nb_www
    - ratio_digits_url
    - phish_hints
    - nb_hyperlinks
    
    K=3, Manhattan distance, MinMaxScaler
    Test accuracy: 89.4%
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize KNN analyzer.
        
        Args:
            model_path: Path to seed_model.json (default: saved_models/seed_model.json)
        """
        self.model_path = Path(model_path) if model_path else Path("saved_models/seed_model.json")
        self.model_data = None
        self.k = 3
        self.metric = "manhattan"
        
        if self.model_path.exists():
            self._load_model()
        else:
            logger.warning(f"KNN model not found at {self.model_path}")
    
    def _load_model(self) -> None:
        """Load the pre-trained KNN model from JSON."""
        try:
            with open(self.model_path) as f:
                self.model_data = json.load(f)
            
            logger.info(f"Loaded KNN model: k={self.model_data.get('k')}, metric={self.model_data.get('metric')}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    async def analyze(self, url: str) -> Optional[ModelPrediction]:
        """
        Analyze URL using KNN model.
        
        Extracts 11 features and computes distance to training points.
        Returns prediction based on k-nearest neighbors.
        """
        if not self.model_data:
            return None
        
        try:
            features = self._extract_features(url)
            scaled_features = self._scale_features(features)
            prob_phishing, confidence = self._knn_predict(scaled_features)

            # URL-only scans lack nb_hyperlinks (a real model feature), so the
            # lexical KNN is a WEAK standalone signal - cap its confidence so a
            # lone KNN vote cannot force a block. The extension supplies
            # nb_hyperlinks from the live DOM; that path keeps full confidence.
            url_only = features[10] == 0.0
            if url_only:
                confidence = min(confidence, 0.5)

            return ModelPrediction(
                model_name="phishing_knn",
                malicious_probability=prob_phishing,
                confidence=confidence,
                reasoning=f"KNN prediction: {prob_phishing*100:.1f}% phishing "
                          f"(k=3, Manhattan{'; URL-only, low confidence' if url_only else ''})",
                evidence={
                    "features": {
                        self.model_data["feature_names"][i]: features[i]
                        for i in range(len(features))
                    },
                    "k": self.k,
                    "metric": self.metric,
                    "url_only": url_only,
                    "model_accuracy": 0.894,
                }
            )
        except Exception as e:
            logger.error(f"KNN analysis failed: {e}")
            return None
    
    # Parity-critical: these are the EXACT tokens + formulas extension/features.js
    # uses to build the vectors the seed model was trained on. Any divergence
    # feeds the KNN wrong distances and causes false positives on legit sites.
    _PHISH_HINTS = (
        "wp", "login", "includes", "admin", "content", "site", "images", "js",
        "alibaba", "css", "myaccount", "dropbox", "themes", "plugins", "signin",
        "view",
    )

    @staticmethod
    def _count_sub(s: str, sub: str) -> int:
        """Non-overlapping substring count - identical to Python str.count / JS split-len-1."""
        return s.count(sub)

    def _extract_features(self, url: str, nb_hyperlinks: float = 0.0) -> List[float]:
        """11 features in seed_model.json feature_names order, matching features.js."""
        from urllib.parse import urlparse

        url = url or ""
        low = url.lower()
        hostname = (urlparse(url).hostname or "")
        digits = sum(c.isdigit() for c in url)
        phish_hints = sum(self._count_sub(low, h) for h in self._PHISH_HINTS)

        return [
            float(len(url)),                                   # length_url
            float(len(hostname)),                              # length_hostname
            float(self._count_sub(url, ".")),                  # nb_dots
            float(self._count_sub(url, "-")),                  # nb_hyphens
            float(self._count_sub(url, "?")),                  # nb_qm
            float(self._count_sub(url, "=")),                  # nb_eq
            float(self._count_sub(url, "/")),                  # nb_slash
            float(self._count_sub(url, "www")),                # nb_www  (COUNT, not boolean)
            (digits / len(url)) if url else 0.0,               # ratio_digits_url
            float(phish_hints),                                # phish_hints
            float(nb_hyperlinks) if nb_hyperlinks else 0.0,    # nb_hyperlinks (DOM; 0 for URL-only)
        ]
    
    def _scale_features(self, features: List[float]) -> List[float]:
        """Apply MinMaxScaler to features."""
        if not self.model_data or "scaler" not in self.model_data:
            return features
        
        scaler = self.model_data["scaler"]
        min_vals = scaler.get("min", [])
        scale_vals = scaler.get("scale", [])
        
        scaled = []
        for i, feat in enumerate(features):
            if i < len(min_vals) and i < len(scale_vals):
                # x_scaled = x * scale + min
                scaled_val = feat * scale_vals[i] + min_vals[i]
                scaled.append(scaled_val)
            else:
                scaled.append(feat)
        
        return scaled
    
    def _knn_predict(self, scaled_features: List[float]) -> tuple:
        """
        K-NN prediction using Manhattan distance.
        
        Returns:
            (probability_phishing, confidence)
        """
        if not self.model_data or "X" not in self.model_data:
            return 0.5, 0.5
        
        X = self.model_data["X"]  # Training points (scaled)
        y = self.model_data["y"]  # Labels (0=legitimate, 1=phishing)
        
        # Compute distances to all training points
        distances = []
        for x_train in X:
            dist = sum(abs(scaled_features[i] - x_train[i]) for i in range(len(scaled_features)))
            distances.append(dist)
        
        # Find k-nearest neighbors
        k_nearest_indices = sorted(range(len(distances)), key=lambda i: distances[i])[:self.k]
        k_nearest_labels = [y[i] for i in k_nearest_indices]
        
        # Majority vote
        phishing_count = sum(k_nearest_labels)
        prob_phishing = phishing_count / self.k
        confidence = abs(phishing_count - (self.k - phishing_count)) / self.k
        
        return prob_phishing, confidence


class URLFeatureAnalyzer(PhishingAnalyzer):
    """
    Enhanced URL feature analysis.
    
    Extends basic features with:
    - Entropy analysis
    - Special character clustering
    - Homograph detection
    - Suspicious TLD detection
    """
    
    async def analyze(self, url: str) -> Optional[ModelPrediction]:
        """Analyze URL structure for phishing indicators."""
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            risk_indicators = 0
            max_risk = 0
            
            # Check for IP-based URL
            hostname = parsed.hostname or ""
            if self._is_ip_address(hostname):
                risk_indicators += 1
                max_risk += 1
            
            # Check for suspicious TLDs
            if self._has_suspicious_tld(hostname):
                risk_indicators += 1
            max_risk += 1
            
            # Check for punycode/unicode tricks
            if self._has_homograph_risk(hostname):
                risk_indicators += 1
            max_risk += 1
            
            # Check for excessive subdomains
            if hostname.count(".") > 3:
                risk_indicators += 1
            max_risk += 1
            
            prob_phishing = risk_indicators / max_risk if max_risk > 0 else 0.0
            
            return ModelPrediction(
                model_name="phishing_url_features",
                malicious_probability=prob_phishing,
                confidence=0.7,
                reasoning=f"URL analysis: {risk_indicators}/{max_risk} risk factors detected",
                evidence={
                    "ip_based": self._is_ip_address(hostname),
                    "suspicious_tld": self._has_suspicious_tld(hostname),
                    "homograph_risk": self._has_homograph_risk(hostname),
                    "subdomain_count": hostname.count("."),
                }
            )
        except Exception as e:
            logger.error(f"URL feature analysis failed: {e}")
            return None
    
    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Check if hostname is an IP address."""
        import re
        ip_pattern = r"^(\d+\.){3}\d+$"
        return bool(re.match(ip_pattern, hostname))
    
    @staticmethod
    def _has_suspicious_tld(hostname: str) -> bool:
        """Check for suspicious TLDs commonly used in phishing."""
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".pw", ".xyz"]
        return any(hostname.lower().endswith(tld) for tld in suspicious_tlds)
    
    @staticmethod
    def _has_homograph_risk(hostname: str) -> bool:
        """Check for homograph attack patterns."""
        # Punycode URLs
        if hostname.startswith("xn--"):
            return True
        
        # Mixed scripts (Cyrillic + Latin, etc)
        # This is a simplified check
        if any(ord(c) > 127 for c in hostname):
            return True
        
        return False


class DomainLookalikeAnalyzer(PhishingAnalyzer):
    """
    Domain lookalike detection using edit distance and character similarity.
    
    Identifies typosquatting and homograph attacks by comparing against
    known legitimate domains.
    """
    
    def __init__(self, legitimate_domains: Optional[List[str]] = None):
        """
        Initialize lookalike analyzer.
        
        Args:
            legitimate_domains: List of legitimate domains to compare against
        """
        self.legitimate_domains = legitimate_domains or self._get_default_domains()
    
    # Brands whose names, when they appear in a NON-official domain, strongly
    # indicate impersonation.
    _BRANDS = ("paypal", "apple", "icloud", "microsoft", "office365", "outlook",
               "google", "gmail", "amazon", "netflix", "facebook", "instagram",
               "whatsapp", "chase", "wellsfargo", "bankofamerica", "citibank",
               "coinbase", "binance", "dhl", "fedex", "ups", "usps", "irs",
               "linkedin", "dropbox", "docusign", "steam")
    _BRAND_TLDS = {b + ".com" for b in _BRANDS} | {
        "paypal.com", "apple.com", "icloud.com", "microsoft.com", "live.com",
        "office.com", "google.com", "gmail.com", "amazon.com", "netflix.com",
        "facebook.com", "instagram.com", "chase.com", "coinbase.com",
        "binance.com", "dhl.com", "fedex.com", "linkedin.com", "dropbox.com",
    }
    _RISKY_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
                   ".link", ".zip", ".review", ".country", ".kim", ".work")
    _HOMOGLYPH_SUBS = {"0": "o", "1": "l", "3": "e", "5": "s", "rn": "m", "vv": "w"}

    async def analyze(self, url: str) -> Optional[ModelPrediction]:
        """Detect domain lookalike / typosquat / brand-impersonation attacks."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url if "://" in url else "http://" + url)
            hostname = (parsed.hostname or "").lower()
            labels = hostname.split(".")
            reg = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
            main_label = labels[-2] if len(labels) >= 2 else hostname

            risk = 0.0
            reasons: List[str] = []
            deterministic = False

            if hostname and reg not in self._BRAND_TLDS:
                for brand in self._BRANDS:
                    if brand in hostname:
                        # brand name present but this is not the brand's real domain
                        risk = max(risk, 0.9)
                        reasons.append(f"brand '{brand}' in non-official domain '{hostname}'")
                        deterministic = True
                        break
                # digit/homoglyph substitution turns main label into a brand
                deglyph = main_label
                for a, b in self._HOMOGLYPH_SUBS.items():
                    deglyph = deglyph.replace(a, b)
                for brand in self._BRANDS:
                    if deglyph != main_label and (brand in deglyph
                                                  or self._edit_distance(deglyph, brand) <= 1):
                        risk = max(risk, 0.88)
                        reasons.append(f"typosquat of '{brand}' via character substitution ('{main_label}')")
                        deterministic = True
                        break
                # 1-2 edit typosquat of a well-known main label
                for good in ("paypal", "google", "amazon", "apple", "microsoft",
                             "facebook", "netflix", "youtube", "wikipedia"):
                    d = self._edit_distance(main_label, good)
                    if 0 < d <= 1:
                        risk = max(risk, 0.85)
                        reasons.append(f"1-edit typosquat of '{good}' ('{main_label}')")
                        deterministic = True

            # punycode / non-ascii host
            if hostname.startswith("xn--") or any(ord(c) > 127 for c in hostname):
                risk = max(risk, 0.8)
                reasons.append("internationalised / punycode domain (possible homograph)")
                deterministic = True

            # brand keyword + risky free TLD (softer signal)
            if any(hostname.endswith(t) for t in self._RISKY_TLDS):
                if any(k in url.lower() for k in ("login", "verify", "account",
                                                  "secure", "update", "signin", "confirm")):
                    risk = max(risk, 0.6)
                    reasons.append("credential keyword on a free/abused TLD")

            return ModelPrediction(
                model_name="phishing_domain_lookalike",
                malicious_probability=round(risk, 3),
                confidence=0.9 if deterministic else 0.6,
                reasoning=("Domain lookalike: " + "; ".join(reasons)) if reasons
                          else "Domain lookalike analysis: no impersonation pattern",
                evidence={
                    "domain": reg,
                    "hostname": hostname,
                    "indicators": reasons,
                    "deterministic": deterministic,
                    "typosquatting_risk": risk >= 0.5,
                    "signature_match": deterministic and risk >= 0.85,
                },
            )
        except Exception as e:
            logger.error(f"Lookalike analysis failed: {e}")
            return None
    
    @staticmethod
    def _edit_distance(s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return DomainLookalikeAnalyzer._edit_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    @staticmethod
    def _get_default_domains() -> List[str]:
        """Get default list of major legitimate domains."""
        return [
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "paypal.com", "twitter.com", "instagram.com",
            "linkedin.com", "netflix.com", "wikipedia.org", "youtube.com",
        ]


class PhishingEngine:
    """
    Central phishing detection engine.
    
    Coordinates multiple phishing analyzers:
    - KNN model (existing, 89.4% accuracy)
    - URL feature analysis
    - Domain lookalike detection
    - [Future] HTML/DOM analysis
    - [Future] NLP analysis
    - [Future] Visual analysis
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize phishing engine."""
        self.analyzers: List[PhishingAnalyzer] = []
        
        # Register existing analyzers
        self.knn = KNNPhishingAnalyzer(model_path)
        self.analyzers.append(self.knn)
        
        # Register new analyzers
        self.url_features = URLFeatureAnalyzer()
        self.analyzers.append(self.url_features)
        
        self.lookalike = DomainLookalikeAnalyzer()
        self.analyzers.append(self.lookalike)
        
        logger.info(f"Phishing engine initialized with {len(self.analyzers)} analyzers")
    
    async def analyze(self, url: str) -> Optional[ModelPrediction]:
        """
        Analyze URL using all available analyzers.
        
        This is a placeholder - the orchestrator will collect predictions
        from all analyzers and perform ensemble voting.
        
        For now, return the primary KNN prediction.
        """
        return await self.knn.analyze(url)
    
    async def analyze_all(self, url: str) -> List[ModelPrediction]:
        """Analyze URL with all analyzers and return all predictions."""
        predictions = []
        
        for analyzer in self.analyzers:
            try:
                prediction = await analyzer.analyze(url)
                if prediction:
                    predictions.append(prediction)
            except Exception as e:
                logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
        
        return predictions

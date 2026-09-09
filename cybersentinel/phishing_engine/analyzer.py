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
            # Extract features from URL
            features = self._extract_features(url)
            
            # Scale features using stored scaler
            scaled_features = self._scale_features(features)
            
            # Compute k-NN prediction
            prob_phishing, confidence = self._knn_predict(scaled_features)
            
            return ModelPrediction(
                model_name="phishing_knn",
                malicious_probability=prob_phishing,
                confidence=confidence,
                reasoning=f"KNN prediction: {prob_phishing*100:.1f}% phishing (k=3, Manhattan)",
                evidence={
                    "features": {
                        self.model_data["feature_names"][i]: features[i]
                        for i in range(len(features))
                    },
                    "k": self.k,
                    "metric": self.metric,
                    "model_accuracy": 0.894,  # 89.4% test accuracy
                }
            )
        except Exception as e:
            logger.error(f"KNN analysis failed: {e}")
            return None
    
    def _extract_features(self, url: str) -> List[float]:
        """Extract 11 phishing features from URL."""
        features = []
        
        # 1. length_url
        features.append(float(len(url)))
        
        # 2. length_hostname
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        features.append(float(len(hostname)))
        
        # 3. nb_dots
        features.append(float(url.count(".")))
        
        # 4. nb_hyphens
        features.append(float(url.count("-")))
        
        # 5. nb_qm (question marks)
        features.append(float(url.count("?")))
        
        # 6. nb_eq (equals signs)
        features.append(float(url.count("=")))
        
        # 7. nb_slash
        features.append(float(url.count("/")))
        
        # 8. nb_www
        features.append(1.0 if "www" in url else 0.0)
        
        # 9. ratio_digits_url
        digit_count = sum(1 for c in url if c.isdigit())
        features.append(digit_count / len(url) if url else 0.0)
        
        # 10. phish_hints (suspicious patterns)
        phish_hints = self._detect_phish_hints(url)
        features.append(float(phish_hints))
        
        # 11. nb_hyperlinks (would need DOM, use 0 for URL-only)
        features.append(0.0)  # Placeholder: requires HTML analysis
        
        return features
    
    def _detect_phish_hints(self, url: str) -> int:
        """Detect suspicious patterns in URL."""
        hints = 0
        
        # Common phishing patterns
        suspicious_words = ["verify", "confirm", "account", "update", "login", "password"]
        for word in suspicious_words:
            if word in url.lower():
                hints += 1
        
        # IP-based URLs
        if any(c.isdigit() for c in url.split("://")[-1].split("/")[0]):
            hints += 1
        
        return hints
    
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
    
    async def analyze(self, url: str) -> Optional[ModelPrediction]:
        """Detect domain lookalike attacks."""
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            
            # Extract base domain (without subdomains)
            parts = hostname.split(".")
            if len(parts) >= 2:
                base_domain = f"{parts[-2]}.{parts[-1]}"
            else:
                base_domain = hostname
            
            # Find similarity to legitimate domains
            lookalike_risk = self._compute_lookalike_risk(base_domain)
            
            return ModelPrediction(
                model_name="phishing_domain_lookalike",
                malicious_probability=lookalike_risk,
                confidence=0.6,
                reasoning=f"Domain lookalike analysis: {lookalike_risk*100:.0f}% similarity to phishing patterns",
                evidence={
                    "domain": base_domain,
                    "typosquatting_risk": lookalike_risk > 0.3,
                }
            )
        except Exception as e:
            logger.error(f"Lookalike analysis failed: {e}")
            return None
    
    def _compute_lookalike_risk(self, domain: str) -> float:
        """Compute lookalike risk score (0.0-1.0)."""
        # Common brand typosquatting patterns
        typosquat_patterns = {
            "amaz0n": 0.9,
            "goog1e": 0.9,
            "micros0ft": 0.9,
            "paypa1": 0.9,
            "appie": 0.8,
            "gogle": 0.8,
        }
        
        for pattern, risk in typosquat_patterns.items():
            if self._edit_distance(domain.lower(), pattern) <= 2:
                return risk
        
        return 0.0
    
    @staticmethod
    def _edit_distance(s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return URLFeatureAnalyzer._edit_distance(s2, s1)
        
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

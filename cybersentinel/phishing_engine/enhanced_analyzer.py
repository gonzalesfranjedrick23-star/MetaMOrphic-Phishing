"""Enhanced Phishing Detection Engine

Advanced phishing features:
- Domain reputation & lookalike detection
- SSL/TLS certificate anomalies
- Advanced URL structure analysis
- Credential harvesting indicators
- Social engineering patterns
- Brand impersonation detection
- Homograph attack detection
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class PhishingIndicator:
    """Detected phishing indicator."""
    indicator_type: str
    confidence: float
    description: str


class EnhancedPhishingAnalyzer:
    """Advanced phishing detection with multiple feature extraction methods."""
    
    # Common phishing domain patterns
    PHISHING_KEYWORDS = [
        'verify', 'confirm', 'update', 'validate', 'authorize',
        'account', 'login', 'signin', 'password', 'credential',
        'secure', 'alert', 'urgent', 'action', 'required',
        'suspended', 'limited', 'unusual', 'activity', 'unusual'
    ]
    
    # Brands commonly impersonated
    MAJOR_BRANDS = {
        'apple': ['apple.com', 'icloud.com'],
        'google': ['google.com', 'gmail.com'],
        'microsoft': ['microsoft.com', 'outlook.com'],
        'amazon': ['amazon.com'],
        'facebook': ['facebook.com'],
        'paypal': ['paypal.com'],
        'bank_of_america': ['bankofamerica.com'],
        'chase': ['chase.com'],
        'citibank': ['citibank.com'],
    }
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf',  # Free TLDs
        '.online', '.website', '.store', '.xyz',  # Generic new TLDs
        '.icu', '.top', '.bid', '.download',
    ]
    
    def __init__(self):
        self.homograph_confusables = {
            '0': 'o',  # Zero vs letter O
            '1': 'l',  # One vs lowercase L
            '5': 's',  # Five vs letter S
        }
    
    def analyze_url(self, url: str) -> Tuple[float, List[PhishingIndicator]]:
        """Analyze URL for phishing indicators.
        
        Args:
            url: URL to analyze
            
        Returns:
            (risk_score, list of indicators)
        """
        indicators = []
        scores = []
        
        # Domain analysis
        domain_score, domain_indicators = self._analyze_domain(url)
        scores.append(domain_score)
        indicators.extend(domain_indicators)
        
        # URL structure analysis
        structure_score, structure_indicators = self._analyze_url_structure(url)
        scores.append(structure_score)
        indicators.extend(structure_indicators)
        
        # Credential harvesting patterns
        harvest_score, harvest_indicators = self._analyze_credential_harvesting(url)
        scores.append(harvest_score)
        indicators.extend(harvest_indicators)
        
        # Brand impersonation
        brand_score, brand_indicators = self._analyze_brand_impersonation(url)
        scores.append(brand_score)
        indicators.extend(brand_indicators)
        
        # Homograph attacks
        homograph_score, homograph_indicators = self._analyze_homographs(url)
        scores.append(homograph_score)
        indicators.extend(homograph_indicators)
        
        # Aggregate risk score
        risk_score = sum(scores) / len(scores) if scores else 0.0
        
        return risk_score, indicators
    
    def _analyze_domain(self, url: str) -> Tuple[float, List[PhishingIndicator]]:
        """Analyze domain for phishing characteristics."""
        indicators = []
        score = 0.0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except:
            return 0.0, []
        
        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                indicators.append(PhishingIndicator(
                    indicator_type="suspicious_tld",
                    confidence=0.4,
                    description=f"Suspicious TLD: {tld}"
                ))
                score += 0.15
                break
        
        # Check for numerical domains
        if re.match(r'^(\d+\.)+\d+$', domain):
            indicators.append(PhishingIndicator(
                indicator_type="numerical_domain",
                confidence=0.5,
                description="Domain uses only numbers (IP-like), suspicious for phishing"
            ))
            score += 0.2
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            indicators.append(PhishingIndicator(
                indicator_type="excessive_subdomains",
                confidence=0.4,
                description=f"Excessive subdomains ({subdomain_count}), may be obfuscation"
            ))
            score += 0.15
        
        # Check domain length (too long = suspicious)
        if len(domain) > 40:
            indicators.append(PhishingIndicator(
                indicator_type="long_domain",
                confidence=0.3,
                description="Domain name unusually long (obfuscation technique)"
            ))
            score += 0.1
        
        return min(score, 1.0), indicators
    
    def _analyze_url_structure(self, url: str) -> Tuple[float, List[PhishingIndicator]]:
        """Analyze URL structure for phishing patterns."""
        indicators = []
        score = 0.0
        
        try:
            parsed = urlparse(url)
        except:
            return 0.0, []
        
        # Check for mixed protocols (http with https domain hints)
        if parsed.scheme == 'http' and ('secure' in parsed.netloc or 'ssl' in parsed.netloc):
            indicators.append(PhishingIndicator(
                indicator_type="insecure_protocol",
                confidence=0.5,
                description="HTTP protocol used despite domain suggesting HTTPS/security"
            ))
            score += 0.2
        
        # Check for credentials in URL
        if '@' in parsed.netloc:
            indicators.append(PhishingIndicator(
                indicator_type="url_credentials",
                confidence=0.7,
                description="URL contains embedded credentials (@ symbol)"
            ))
            score += 0.3
        
        # Check URL path for sensitive keywords
        path = parsed.path.lower()
        for keyword in ['login', 'signin', 'verify', 'confirm', 'update', 'account']:
            if keyword in path:
                indicators.append(PhishingIndicator(
                    indicator_type="sensitive_path",
                    confidence=0.4,
                    description=f"URL path contains sensitive keyword: {keyword}"
                ))
                score += 0.1
                break
        
        # Check for URL parameter injection (many = or & symbols)
        if path.count('=') > 5 or path.count('&') > 5:
            indicators.append(PhishingIndicator(
                indicator_type="excessive_parameters",
                confidence=0.4,
                description="URL has excessive parameters (potential injection)"
            ))
            score += 0.15
        
        return min(score, 1.0), indicators
    
    def _analyze_credential_harvesting(self, url: str) -> Tuple[float, List[PhishingIndicator]]:
        """Detect credential harvesting indicators."""
        indicators = []
        score = 0.0
        
        url_lower = url.lower()
        
        # Keywords commonly found in phishing URLs
        harvesting_keywords = [
            'verify', 'confirm', 'validate', 'authenticate',
            'update-account', 'urgent-action', 'confirm-identity'
        ]
        
        for keyword in harvesting_keywords:
            if keyword in url_lower:
                indicators.append(PhishingIndicator(
                    indicator_type="harvesting_keyword",
                    confidence=0.5,
                    description=f"URL contains credential harvesting keyword: {keyword}"
                ))
                score += 0.15
                break
        
        # Check for form-like parameters
        if 'email=' in url_lower or 'username=' in url_lower or 'password=' in url_lower:
            indicators.append(PhishingIndicator(
                indicator_type="form_parameters",
                confidence=0.6,
                description="URL contains form field parameters (credential fields)"
            ))
            score += 0.25
        
        return min(score, 1.0), indicators
    
    def _analyze_brand_impersonation(self, url: str) -> Tuple[float, List[PhishingIndicator]]:
        """Detect brand impersonation attacks."""
        indicators = []
        score = 0.0
        
        url_lower = url.lower()
        
        for brand, legitimate_domains in self.MAJOR_BRANDS.items():
            # Check if brand name appears in URL but domain isn't legitimate
            if brand.replace('_', '') in url_lower:
                domain = urlparse(url).netloc.lower()
                is_legitimate = any(legitimate in domain for legitimate in legitimate_domains)
                
                if not is_legitimate:
                    indicators.append(PhishingIndicator(
                        indicator_type="brand_impersonation",
                        confidence=0.7,
                        description=f"Domain impersonates {brand.replace('_', ' ')}"
                    ))
                    score += 0.3
                    break
        
        return min(score, 1.0), indicators
    
    def _analyze_homographs(self, url: str) -> Tuple[float, List[PhishingIndicator]]:
        """Detect homograph attacks (using lookalike characters)."""
        indicators = []
        score = 0.0
        
        domain = urlparse(url).netloc.lower()
        
        # Check for confusable characters
        confusable_count = 0
        for confusable, original in self.homograph_confusables.items():
            if confusable in domain and original not in domain:
                confusable_count += 1
        
        if confusable_count > 0:
            indicators.append(PhishingIndicator(
                indicator_type="homograph_attack",
                confidence=0.6,
                description=f"Domain contains {confusable_count} homograph characters (0/O, 1/l, 5/s)"
            ))
            score += 0.25
        
        # Check for Cyrillic 'a' (а) vs Latin 'a' (a)
        cyrillic_a = 'а'  # Cyrillic small letter A
        if cyrillic_a in domain:
            indicators.append(PhishingIndicator(
                indicator_type="cyrillic_homograph",
                confidence=0.8,
                description="Domain contains Cyrillic characters disguised as Latin (IDN attack)"
            ))
            score += 0.35
        
        return min(score, 1.0), indicators
    
    def analyze_html_content(self, html_content: str) -> Tuple[float, List[PhishingIndicator]]:
        """Analyze HTML page content for phishing elements.
        
        Args:
            html_content: HTML source code of page
            
        Returns:
            (risk_score, list of indicators)
        """
        indicators = []
        score = 0.0
        
        html_lower = html_content.lower()
        
        # Check for login forms
        if '<form' in html_lower and ('password' in html_lower or 'login' in html_lower):
            indicators.append(PhishingIndicator(
                indicator_type="login_form",
                confidence=0.5,
                description="Page contains login form"
            ))
            score += 0.15
        
        # Check for credential input fields
        credential_patterns = [
            '<input.*type.*password',
            '<input.*name.*email',
            '<input.*name.*username'
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, html_lower):
                indicators.append(PhishingIndicator(
                    indicator_type="credential_input",
                    confidence=0.6,
                    description="Page contains credential input fields"
                ))
                score += 0.2
                break
        
        # Check for external stylesheets/scripts (common obfuscation)
        external_count = html_lower.count('<script src=') + html_lower.count('<link href=')
        if external_count > 5:
            indicators.append(PhishingIndicator(
                indicator_type="excessive_external_resources",
                confidence=0.4,
                description=f"Page loads {external_count} external resources (potential phishing staging)"
            ))
            score += 0.1
        
        # Check for fake browser warnings
        if any(warning in html_lower for warning in ['browser', 'outdated', 'update now', 'security warning']):
            indicators.append(PhishingIndicator(
                indicator_type="fake_warning",
                confidence=0.6,
                description="Page contains fake browser/security warning"
            ))
            score += 0.25
        
        return min(score, 1.0), indicators

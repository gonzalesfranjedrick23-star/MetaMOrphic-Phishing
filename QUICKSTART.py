"""
CyberSentinel Quick Start Guide (Phase 2)

Usage examples for the unified threat detection platform.
"""

# ============================================================================
# 1. BASIC SETUP
# ============================================================================

from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.phishing_engine import PhishingEngine
from cybersentinel.malware_engine import MalwareEngine
from cybersentinel.common import get_event_bus, EventType
import asyncio

async def main():
    # Create orchestrator
    orchestrator = ThreatOrchestrator()
    
    # Create detection engines
    phishing_engine = PhishingEngine()
    malware_engine = MalwareEngine()
    
    # Register engines
    orchestrator.register_phishing_engine("phishing", phishing_engine)
    orchestrator.register_malware_engine("malware", malware_engine)
    
    print("✓ CyberSentinel initialized")
    print(f"✓ Status: {orchestrator.get_status()}")


# ============================================================================
# 2. ANALYZE A URL (PHISHING)
# ============================================================================

async def analyze_url_example():
    orchestrator = ThreatOrchestrator()
    orchestrator.register_phishing_engine("phishing", PhishingEngine())
    
    # Analyze URL
    result = await orchestrator.analyze_url("https://suspicious-domain.tk")
    
    # Check result
    if result.risk_assessment.risk_level.value == "critical":
        print("🚨 CRITICAL THREAT DETECTED")
        print(f"Score: {result.risk_assessment.risk_score}/100")
        print(f"Recommendation: {result.risk_assessment.recommendation}")
    
    # Show explanation
    print(result.risk_assessment.explanation)


# ============================================================================
# 3. ANALYZE A FILE (MALWARE)
# ============================================================================

async def analyze_file_example():
    orchestrator = ThreatOrchestrator()
    orchestrator.register_malware_engine("malware", MalwareEngine())
    
    # Analyze file
    result = await orchestrator.analyze_file("/path/to/suspicious.exe")
    
    # Check models that flagged it
    high_risk_models = [
        p for p in result.risk_assessment.individual_predictions
        if p.malicious_probability > 0.5
    ]
    
    print(f"Models flagged: {len(high_risk_models)}/all")
    for pred in high_risk_models:
        print(f"  - {pred.model_name}: {pred.reasoning}")


# ============================================================================
# 4. LISTEN TO EVENTS
# ============================================================================

def setup_event_listeners():
    bus = get_event_bus()
    
    def on_threat_detected(event):
        data = event.data
        print(f"🚨 THREAT DETECTED")
        print(f"   {data.get('file_path') or data.get('url')}")
        print(f"   Risk: {data.get('risk_score')}/100")
        print(f"   Action: {data.get('recommendation')}")
    
    def on_analysis_completed(event):
        print(f"✓ Analysis complete: {event.data.get('request_id')[:8]}...")
    
    # Subscribe
    bus.subscribe(EventType.THREAT_DETECTED, on_threat_detected)
    bus.subscribe(EventType.ANALYSIS_COMPLETED, on_analysis_completed)


# ============================================================================
# 5. MANAGE PROTECTION LIFECYCLE
# ============================================================================

async def protection_example():
    orchestrator = ThreatOrchestrator()
    
    # Start monitoring
    orchestrator.start_protection()
    print("✓ Protection ACTIVE")
    
    # Analyze threats
    # ... analysis code ...
    
    # Stop monitoring
    orchestrator.stop_protection()
    print("✓ Protection STOPPED")


# ============================================================================
# 6. VIEW DATABASE & HISTORY
# ============================================================================

def database_example():
    orchestrator = ThreatOrchestrator()
    
    # Get statistics
    stats = orchestrator.database.get_statistics()
    print(f"Total threats: {stats['total_threats']}")
    print(f"By type: {stats['threats_by_type']}")
    print(f"By level: {stats['threats_by_level']}")
    print(f"Quarantined: {stats['quarantined_files']}")
    
    # Get threat history
    threats = orchestrator.database.get_threats(threat_type="phishing", limit=10)
    for threat in threats:
        print(f"  {threat.detection_time} - {threat.url} ({threat.risk_level})")


# ============================================================================
# 7. CUSTOMIZE RISK SCORING
# ============================================================================

def risk_scoring_example():
    orchestrator = ThreatOrchestrator()
    
    # View current weights
    weights = orchestrator.risk_scorer.get_model_weights()
    print("Model weights:")
    for model, weight in weights.items():
        print(f"  {model}: {weight}")
    
    # Adjust weights (0.0-2.0 range)
    orchestrator.risk_scorer.set_model_weight("phishing_knn", 1.5)  # Trust KNN more
    orchestrator.risk_scorer.set_model_weight("malware_yara", 1.8)  # Trust YARA more


# ============================================================================
# 8. MULTIPLE ANALYZERS (PHISHING ONLY)
# ============================================================================

async def multiple_phishing_analyzers():
    engine = PhishingEngine()
    
    # Analyze with ALL phishing analyzers
    url = "https://suspicious.example.com"
    all_predictions = await engine.analyze_all(url)
    
    for pred in all_predictions:
        print(f"{pred.model_name}: {pred.malicious_probability*100:.0f}%")


# ============================================================================
# 9. MULTIPLE ANALYZERS (MALWARE ONLY)
# ============================================================================

async def multiple_malware_analyzers():
    engine = MalwareEngine()
    
    # Analyze with ALL malware analyzers
    file_path = "/path/to/file.exe"
    all_predictions = await engine.analyze_all(file_path)
    
    for pred in all_predictions:
        print(f"{pred.model_name}: {pred.malicious_probability*100:.0f}%")


# ============================================================================
# 10. COMPLETE EXAMPLE (FULL WORKFLOW)
# ============================================================================

async def complete_example():
    # Initialize
    orchestrator = ThreatOrchestrator()
    orchestrator.register_phishing_engine("phishing", PhishingEngine())
    orchestrator.register_malware_engine("malware", MalwareEngine())
    
    # Setup event listeners
    bus = get_event_bus()
    
    def on_threat(event):
        print(f"⚠️  Threat: {event.data}")
    
    bus.subscribe(EventType.THREAT_DETECTED, on_threat)
    
    # Start protection
    orchestrator.start_protection()
    
    # Analyze URLs
    urls = [
        "https://www.google.com",
        "https://malicious-phishing.tk",
        "https://amaz0n-verify.xyz"
    ]
    
    for url in urls:
        result = await orchestrator.analyze_url(url)
        print(f"\n{url}")
        print(f"  Risk: {result.risk_assessment.risk_level.value.upper()}")
        print(f"  Score: {result.risk_assessment.risk_score:.1f}/100")
        print(f"  Recommendation: {result.risk_assessment.recommendation}")
    
    # Stop protection
    orchestrator.stop_protection()
    
    # Show statistics
    stats = orchestrator.database.get_statistics()
    print(f"\nAnalysis complete. Threats detected: {stats['total_threats']}")


# ============================================================================
# RUN EXAMPLES
# ============================================================================

if __name__ == "__main__":
    print("CyberSentinel Quick Start Examples\n")
    
    # Run the complete example
    asyncio.run(complete_example())

"""Phase 4 Integration Test

Demonstrates:
- Metamorphic malware detection
- Media file scanning
- Enhanced phishing detection
- Web API endpoints
- Real-time monitoring
"""

import asyncio
import json
import tempfile
from pathlib import Path

from cybersentinel.common.event_bus import EventBus, EventType
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.malware_engine.metamorphic_detector import MetamorphicMalwareDetector
from cybersentinel.malware_engine.media_scanner import MediaFileScanner
from cybersentinel.phishing_engine.enhanced_analyzer import EnhancedPhishingAnalyzer
from cybersentinel.monitoring.monitor import FileMonitor
from cybersentinel.common.risk_scorer import RiskScorer


def test_metamorphic_detection():
    """Test metamorphic malware detection."""
    print("\n" + "=" * 70)
    print("TEST 1: Metamorphic Malware Detection")
    print("=" * 70)
    
    detector = MetamorphicMalwareDetector()
    
    # Create mock binary with high entropy (simulating packed malware)
    mock_binary = b'MZ' + b'\x00\x01\x02\x03' * 1000 + b'GetProcAddress' * 50
    
    risk_score, indicators = detector.analyze_binary(mock_binary)
    
    print(f"Risk Score: {risk_score:.2f}")
    print(f"Risk Level: {detector.get_risk_level(risk_score)}")
    print(f"Indicators Found: {len(indicators)}")
    
    for indicator in indicators[:5]:
        print(f"  • {indicator.indicator_type} (confidence: {indicator.confidence:.1%})")
        print(f"    {indicator.description}")


def test_metamorphic_layer_catalog():
    """The metamorphic prediction exposes all requested layers honestly."""
    detector = MetamorphicMalwareDetector()
    prediction = asyncio.run(detector.analyze("tests/../saved_models/seed_model.json"))
    layers = prediction.evidence["layers"]

    assert len(layers) == 25
    assert [layer["number"] for layer in layers] == list(range(1, 26))
    assert layers[0]["status"] == "implemented"
    assert layers[0]["evidence"]["sha256"]
    assert layers[18]["status"] == "not_configured"
    assert layers[23]["status"] == "implemented"


def test_central_score_validator_clamps_to_100_percent():
    """The shared risk scorer is the single score validation boundary for all UI/API consumers."""
    scorer = RiskScorer()
    assert scorer.validate_score(150.0) == 100.0
    assert scorer.validate_score(-30.0) == 0.0
    assert scorer.validate_score(42.5) == 42.5


def test_media_scanning():
    """Test media file threat scanning."""
    print("\n" + "=" * 70)
    print("TEST 2: Media File Scanner")
    print("=" * 70)
    
    scanner = MediaFileScanner()
    
    # Test 1: PDF with JavaScript
    print("\n--- PDF with JavaScript ---")
    pdf_data = b'%PDF-1.4\nJavaScript /OpenAction << /AA << /OpenAction << /JS (alert(1)) >> >> >>'
    
    # Create actual test file
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
        f.write(pdf_data)
        temp_pdf = f.name
    
    try:
        risk, threats = scanner.scan_file(temp_pdf)
        print(f"Risk Score: {risk:.2f}")
        print(f"Threats: {len(threats)}")
        for threat in threats[:3]:
            print(f"  • {threat.threat_type}: {threat.description}")
    finally:
        Path(temp_pdf).unlink()
    
    # Test 2: Office document with macros
    print("\n--- Office Document with Macros ---")
    doc_data = b'\xd0\xcf\x11\xe0' + b'VBA_PROJECT' + b'AutoOpen' * 10
    
    with tempfile.NamedTemporaryFile(suffix='.doc', delete=False) as f:
        f.write(doc_data)
        temp_doc = f.name
    
    try:
        risk, threats = scanner.scan_file(temp_doc)
        print(f"Risk Score: {risk:.2f}")
        print(f"Threats: {len(threats)}")
        for threat in threats[:3]:
            print(f"  • {threat.threat_type}: {threat.description}")
    finally:
        Path(temp_doc).unlink()


def test_enhanced_phishing():
    """Test enhanced phishing detection."""
    print("\n" + "=" * 70)
    print("TEST 3: Enhanced Phishing Detection")
    print("=" * 70)
    
    analyzer = EnhancedPhishingAnalyzer()
    
    # Test phishing URLs
    test_urls = [
        "http://apple-verify-account.tk/login/verify-email",
        "https://www.apple.com/",
        "http://192.168.1.1/confirm-identity",
        "https://verify-chase-banking.online/account",
    ]
    
    for url in test_urls:
        print(f"\n--- Analyzing: {url} ---")
        risk_score, indicators = analyzer.analyze_url(url)
        
        print(f"Risk Score: {risk_score:.2f}")
        print(f"Indicators: {len(indicators)}")
        
        for indicator in indicators[:3]:
            print(f"  • {indicator.indicator_type} (confidence: {indicator.confidence:.1%})")
            print(f"    {indicator.description}")


def test_html_phishing():
    """Test HTML content analysis."""
    print("\n" + "=" * 70)
    print("TEST 4: HTML Phishing Content Analysis")
    print("=" * 70)
    
    analyzer = EnhancedPhishingAnalyzer()
    
    html = """
    <html>
    <body>
    <form method="POST" action="/login">
        <input type="text" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <button>Verify Account</button>
    </form>
    </body>
    </html>
    """
    
    risk_score, indicators = analyzer.analyze_html_content(html)
    
    print(f"Risk Score: {risk_score:.2f}")
    print(f"Indicators: {len(indicators)}")
    
    for indicator in indicators:
        print(f"  • {indicator.indicator_type}: {indicator.description}")


def test_orchestrator_with_new_engines():
    """Test orchestrator with new detection engines."""
    print("\n" + "=" * 70)
    print("TEST 5: Orchestrator with Enhanced Engines")
    print("=" * 70)

    async def run_checks():
        bus = EventBus()
        orchestrator = ThreatOrchestrator(event_bus=bus)

        # Test URL analysis
        print("\n--- URL Analysis ---")
        url = "https://verify-amazon-account.tk/login"
        result = await orchestrator.analyze_url(url)

        print(f"URL: {url}")
        print(f"Risk Level: {result.risk_assessment.risk_level}")
        print(f"Risk Score: {result.risk_assessment.risk_score:.2f}")
        print(f"Recommendation: {result.risk_assessment.recommendation}")

        # Test file analysis
        print("\n--- File Analysis ---")
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00\x01' * 500)  # Mock PE file
            temp_file = f.name

        try:
            result = await orchestrator.analyze_file(temp_file)
            print(f"File: {Path(temp_file).name}")
            print(f"Risk Level: {result.risk_assessment.risk_level}")
            print(f"Risk Score: {result.risk_assessment.risk_score:.2f}")
            print(f"Analysis Time: {result.analysis_time_ms:.1f}ms")
        finally:
            Path(temp_file).unlink()

    asyncio.run(run_checks())


def test_monitoring_integration():
    """Test real-time monitoring with new detection."""
    print("\n" + "=" * 70)
    print("TEST 6: Real-time Monitoring Integration")
    print("=" * 70)
    
    bus = EventBus()
    events_captured = []
    
    def capture_event(event):
        events_captured.append(event.event_type.value)
    
    # Subscribe to file events
    bus.subscribe(EventType.FILE_CREATED, capture_event)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        monitor = FileMonitor(paths=[tmpdir], event_bus=bus, poll_interval=0.05)
        monitor.start()
        
        # Create test files
        import time
        (Path(tmpdir) / "test1.txt").write_text("benign file")
        (Path(tmpdir) / "test2.pdf").write_bytes(b'%PDF-1.4\nJavaScript')
        
        time.sleep(0.3)
        monitor.stop()
        
        print(f"Events Captured: {len(events_captured)}")
        print(f"Files Detected: {events_captured}")


def test_extension_manifest_declares_navigation_and_host_permissions():
    """The extension contract must advertise the browser navigation event API
    and the HTTP(S) host surface that the service worker uses for page telemetry.
    """
    manifest_path = Path(__file__).resolve().parents[1] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert "webNavigation" in manifest["permissions"]
    assert "http://*/*" in manifest["host_permissions"]
    assert "https://*/*" in manifest["host_permissions"]


def run_all_tests():
    """Run all Phase 4 tests."""
    print("\n" + "=" * 70)
    print("CyberSentinel Phase 4 Integration Tests")
    print("=" * 70)
    
    try:
        test_metamorphic_detection()
        test_media_scanning()
        test_enhanced_phishing()
        test_html_phishing()
        test_orchestrator_with_new_engines()
        test_monitoring_integration()
        test_extension_manifest_declares_navigation_and_host_permissions()
        
        print("\n" + "=" * 70)
        print("✅ All Phase 4 tests completed successfully")
        print("=" * 70)
    
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_all_tests()

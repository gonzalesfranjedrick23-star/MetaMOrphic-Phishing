"""
CyberSentinel Integration Example

Demonstrates how to use the unified threat detection platform:
1. Initialize all components
2. Start threat protection
3. Analyze files and URLs
4. View results
"""

import asyncio
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

from cybersentinel.common import (
    EventBus,
    Event,
    EventType,
    get_event_bus,
)
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.phishing_engine import PhishingEngine
from cybersentinel.malware_engine import MalwareEngine


class CyberSentinelIntegration:
    """
    Integration example for CyberSentinel.
    
    Shows how to:
    1. Create engines (malware + phishing)
    2. Register with orchestrator
    3. Analyze files and URLs
    4. Display results
    """
    
    def __init__(self):
        """Initialize all components."""
        logger.info("=" * 60)
        logger.info("CyberSentinel: Multilayered Real-Time Threat Detection")
        logger.info("=" * 60)
        
        # Create event bus
        self.event_bus = get_event_bus()
        logger.info("✓ Event bus initialized")
        
        # Create orchestrator
        self.orchestrator = ThreatOrchestrator(self.event_bus)
        logger.info("✓ Orchestrator initialized")
        
        # Create detection engines
        self.phishing_engine = PhishingEngine()
        self.malware_engine = MalwareEngine()
        logger.info("✓ Detection engines created")
        
        # Register engines with orchestrator
        self.orchestrator.register_phishing_engine("main", self.phishing_engine)
        self.orchestrator.register_malware_engine("main", self.malware_engine)
        logger.info("✓ Engines registered with orchestrator")
        
        # Subscribe to events for logging
        self._subscribe_to_events()
    
    def _subscribe_to_events(self):
        """Subscribe to events for logging."""
        def log_event(event: Event):
            logger.info(f"Event: {event.event_type.value}")
        
        self.event_bus.subscribe(EventType.ANALYSIS_COMPLETED, log_event)
        self.event_bus.subscribe(EventType.THREAT_DETECTED, log_event)
    
    async def analyze_url(self, url: str) -> None:
        """Analyze a URL and display results."""
        logger.info(f"\n{'='*60}")
        logger.info(f"Analyzing URL: {url}")
        logger.info('='*60)
        
        try:
            result = await self.orchestrator.analyze_url(url)
            
            # Display results
            logger.info(f"Risk Score: {result.risk_assessment.risk_score:.1f}/100")
            logger.info(f"Risk Level: {result.risk_assessment.risk_level.value.upper()}")
            logger.info(f"Confidence: {result.risk_assessment.consensus_count}/{len(result.risk_assessment.individual_predictions)} models agree")
            logger.info(f"Recommendation: {result.risk_assessment.recommendation}")
            logger.info(f"Analysis time: {result.analysis_time_ms:.1f}ms")
            
            logger.info("\nModel Predictions:")
            for pred in result.risk_assessment.individual_predictions:
                logger.info(f"  • {pred.model_name}: {pred.malicious_probability*100:.0f}% ({pred.confidence*100:.0f}% confidence)")
                logger.info(f"    {pred.reasoning}")
            
            logger.info(f"\n{result.risk_assessment.explanation}")
        
        except Exception as e:
            logger.error(f"Error analyzing URL: {e}")
    
    async def analyze_file(self, file_path: str) -> None:
        """Analyze a file and display results."""
        logger.info(f"\n{'='*60}")
        logger.info(f"Analyzing file: {file_path}")
        logger.info('='*60)
        
        if not Path(file_path).exists():
            logger.error(f"File not found: {file_path}")
            return
        
        try:
            result = await self.orchestrator.analyze_file(file_path)
            
            # Display results
            logger.info(f"Risk Score: {result.risk_assessment.risk_score:.1f}/100")
            logger.info(f"Risk Level: {result.risk_assessment.risk_level.value.upper()}")
            logger.info(f"Confidence: {result.risk_assessment.consensus_count}/{len(result.risk_assessment.individual_predictions)} models agree")
            logger.info(f"Recommendation: {result.risk_assessment.recommendation}")
            logger.info(f"Analysis time: {result.analysis_time_ms:.1f}ms")
            
            logger.info("\nModel Predictions:")
            for pred in result.risk_assessment.individual_predictions:
                logger.info(f"  • {pred.model_name}: {pred.malicious_probability*100:.0f}% ({pred.confidence*100:.0f}% confidence)")
                logger.info(f"    {pred.reasoning}")
            
            logger.info(f"\n{result.risk_assessment.explanation}")
        
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
    
    async def demo(self):
        """Run demonstration."""
        logger.info("\n" + "="*60)
        logger.info("PHASE 2 DEMO: Unified Threat Detection")
        logger.info("="*60)
        
        # Start protection
        logger.info("\nStarting protection...")
        self.orchestrator.start_protection()
        
        # Show status
        status = self.orchestrator.get_status()
        logger.info(f"\nOrchestrator Status:")
        logger.info(f"  Protection Active: {status['protection_active']}")
        logger.info(f"  Malware Engines: {', '.join(status['malware_engines'])}")
        logger.info(f"  Phishing Engines: {', '.join(status['phishing_engines'])}")
        
        # Demo URLs
        demo_urls = [
            "https://www.google.com",
            "https://suspicious-paypal-verify.tk",
            "https://amaz0n-account-update.xyz",
        ]
        
        logger.info("\n" + "-"*60)
        logger.info("PHISHING DETECTION DEMO")
        logger.info("-"*60)
        
        for url in demo_urls:
            await self.analyze_url(url)
            await asyncio.sleep(0.5)
        
        # Stop protection
        logger.info("\n" + "-"*60)
        logger.info("Stopping protection...")
        self.orchestrator.stop_protection()
        
        # Show final statistics
        logger.info("\n" + "="*60)
        logger.info("SUMMARY")
        logger.info("="*60)
        status = self.orchestrator.get_status()
        stats = status.get('database_stats', {})
        logger.info(f"Total threats detected: {stats.get('total_threats', 0)}")
        logger.info(f"Quarantined files: {stats.get('quarantined_files', 0)}")
        
        # Show event history
        history = self.event_bus.get_event_history()
        logger.info(f"\nEvent history ({len(history)} events):")
        for event in history:
            logger.info(f"  {event.timestamp.isoformat()} - {event.event_type.value}")


async def main():
    """Run the integration example."""
    integration = CyberSentinelIntegration()
    await integration.demo()


if __name__ == "__main__":
    asyncio.run(main())

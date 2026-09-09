"""
Event Bus: Core event-driven architecture for CyberSentinel

Handles routing of file/URL events through the detection pipeline.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, List, Dict
from datetime import datetime, timezone
import uuid


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EventType(Enum):
    """Supported event types."""
    
    # File events
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_ACCESSED = "file_accessed"
    FILE_DOWNLOADED = "file_downloaded"
    
    # URL events
    URL_VISITED = "url_visited"
    URL_CLICKED = "url_clicked"
    
    # Process events
    PROCESS_CREATED = "process_created"
    PROCESS_TERMINATED = "process_terminated"
    
    # Analysis events
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    
    # Detection events
    THREAT_DETECTED = "threat_detected"
    THREAT_QUARANTINED = "threat_quarantined"
    
    # System events
    PROTECTION_STARTED = "protection_started"
    PROTECTION_STOPPED = "protection_stopped"
    PROTECTION_ERROR = "protection_error"


@dataclass
class Event:
    """Base event class."""
    
    event_type: EventType
    timestamp: datetime = field(default_factory=_utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""  # Which component generated this event
    data: Dict[str, Any] = field(default_factory=dict)
    
    def __repr__(self) -> str:
        return f"Event({self.event_type.value} @ {self.timestamp.isoformat()})"


class EventBus:
    """
    Central event bus for CyberSentinel.
    
    Manages event publishing and subscription across all components.
    Provides synchronous and asynchronous event handling.
    """
    
    def __init__(self):
        """Initialize the event bus."""
        self._subscribers: Dict[EventType, List[Callable]] = {}
        self._event_history: List[Event] = []
        self._max_history = 10000
        
    def subscribe(self, event_type: EventType, handler: Callable) -> None:
        """
        Subscribe to events of a specific type.
        
        Args:
            event_type: Type of events to listen for
            handler: Callable that processes the event
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)
    
    def unsubscribe(self, event_type: EventType, handler: Callable) -> None:
        """
        Unsubscribe from events of a specific type.
        
        Args:
            event_type: Type of events to stop listening for
            handler: Handler to remove
        """
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                h for h in self._subscribers[event_type] if h != handler
            ]
    
    def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribers.
        
        Args:
            event: Event to publish
        """
        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)
        
        # Notify all subscribers
        if event.event_type in self._subscribers:
            for handler in self._subscribers[event.event_type]:
                try:
                    handler(event)
                except Exception as e:
                    # Log error but don't crash the event bus
                    print(f"Error in event handler for {event.event_type}: {e}")
    
    def get_event_history(self, event_type: EventType = None, limit: int = 100) -> List[Event]:
        """
        Retrieve event history.
        
        Args:
            event_type: Filter by event type (None = all types)
            limit: Maximum number of events to return
            
        Returns:
            List of events, most recent first
        """
        if event_type:
            events = [e for e in self._event_history if e.event_type == event_type]
        else:
            events = self._event_history
        
        return events[-limit:][::-1]  # Reverse for most recent first
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics."""
        return {
            "total_events": len(self._event_history),
            "event_types": {
                et.value: len([e for e in self._event_history if e.event_type == et])
                for et in EventType
            },
            "subscribers": {
                et.value: len(handlers)
                for et, handlers in self._subscribers.items()
                if handlers
            }
        }


# Global event bus instance
_event_bus = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus

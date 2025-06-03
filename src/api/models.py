"""
Data models for Azure DevOps Advanced Security alerts.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any


class AlertType(str, Enum):
    """Alert types in Azure DevOps Advanced Security."""
    CODE = "code"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    """Confidence levels for alerts."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    OTHER = "other"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels for alerts."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    WARNING = "warning"
    NOTE = "note"
    UNKNOWN = "unknown"


class AlertState(str, Enum):
    """Possible states for an alert."""
    ACTIVE = "active"
    DISMISSED = "dismissed"
    FIXED = "fixed"
    UNKNOWN = "unknown"


@dataclass
class PhysicalLocation:
    """Physical location in source code where an issue was found."""
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    
    @classmethod
    def from_api(cls, data: Dict) -> 'PhysicalLocation':
        """Create from API response data."""
        return cls(
            file_path=data.get("filePath", ""),
            start_line=data.get("startLine"),
            end_line=data.get("endLine"),
            start_column=data.get("startColumn"),
            end_column=data.get("endColumn")
        )


@dataclass
class LogicalLocation:
    """Logical location for an alert (e.g., component)."""
    name: str
    kind: Optional[str] = None
    
    @classmethod
    def from_api(cls, data: Dict) -> 'LogicalLocation':
        """Create from API response data."""
        return cls(
            name=data.get("name", ""),
            kind=data.get("kind")
        )


@dataclass
class Rule:
    """Analysis rule that caused an alert."""
    id: str
    name: str
    description: Optional[str] = None
    
    @classmethod
    def from_api(cls, data: Dict) -> 'Rule':
        """Create from API response data."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description")
        )


@dataclass
class Tool:
    """Analysis tool that generated a security alert."""
    name: str
    version: Optional[str] = None
    
    @classmethod
    def from_api(cls, data: Dict) -> 'Tool':
        """Create from API response data."""
        return cls(
            name=data.get("name", ""),
            version=data.get("version")
        )


@dataclass
class Dismissal:
    """Information about an alert dismissal."""
    type: str
    comment: Optional[str] = None
    dismissed_by: Optional[str] = None
    dismissed_at: Optional[datetime] = None
    
    @classmethod
    def from_api(cls, data: Dict) -> Optional['Dismissal']:
        """Create from API response data."""
        if not data:
            return None
            
        return cls(
            type=data.get("type", ""),
            comment=data.get("comment"),
            dismissed_by=data.get("dismissedBy", {}).get("displayName"),
            dismissed_at=datetime.fromisoformat(data.get("dismissedDate")) if data.get("dismissedDate") else None
        )


@dataclass
class Alert:
    """Azure DevOps Advanced Security alert."""
    alert_id: int
    alert_type: AlertType
    confidence: Confidence
    severity: Severity
    state: AlertState
    first_seen_date: datetime
    last_seen_date: datetime
    git_ref: str
    physical_locations: List[PhysicalLocation]
    logical_locations: List[LogicalLocation]
    rule: Optional[Rule] = None
    tool: Optional[Tool] = None
    dismissal: Optional[Dismissal] = None
    introduced_date: Optional[datetime] = None
    fixed_date: Optional[datetime] = None
    additional_properties: Dict[str, Any] = None
    
    @classmethod
    def from_api(cls, data: Dict) -> 'Alert':
        """Create from API response data."""
        # Handle None values for lists
        physical_locations = data.get("physicalLocations", []) or []
        logical_locations = data.get("logicalLocations", []) or []
        
        # Get git_ref from data or use a default value
        git_ref = data.get("gitRef")
        if not git_ref:
            # If gitRef is missing, use the repository name as a fallback
            git_ref = f"refs/heads/{data.get('repository', 'main')}"
        
        return cls(
            alert_id=data.get("alertId", 0),
            alert_type=AlertType(data.get("alertType", "unknown")),
            confidence=Confidence(data.get("confidence", "unknown")),
            severity=Severity(data.get("severity", "unknown")),
            state=AlertState(data.get("state", "unknown")),
            first_seen_date=datetime.fromisoformat(data.get("firstSeenDate")) if data.get("firstSeenDate") else datetime.now(),
            last_seen_date=datetime.fromisoformat(data.get("lastSeenDate")) if data.get("lastSeenDate") else datetime.now(),
            git_ref=git_ref,
            physical_locations=[PhysicalLocation.from_api(loc) for loc in physical_locations],
            logical_locations=[LogicalLocation.from_api(loc) for loc in logical_locations],
            rule=Rule.from_api(data.get("rule", {})) if data.get("rule") else None,
            tool=Tool.from_api(data.get("tool", {})) if data.get("tool") else None,
            dismissal=Dismissal.from_api(data.get("dismissal")) if data.get("dismissal") else None,
            introduced_date=datetime.fromisoformat(data.get("introducedDate")) if data.get("introducedDate") else None,
            fixed_date=datetime.fromisoformat(data.get("fixedDate")) if data.get("fixedDate") else None,
            additional_properties=data.get("additionalProperties", {})
        )

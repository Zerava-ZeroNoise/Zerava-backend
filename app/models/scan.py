"""
Zerava Security Scanner - Scan Model

This module defines the Scan data model representing a security scan operation.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
import uuid


@dataclass
class Scan:
    """
    Represents a security scan operation.
    
    Attributes:
        id: Unique identifier for the scan
        target: URL or endpoint being scanned
        scan_type: Type of scan (full, quick, api, headers)
        status: Current status (pending, running, completed, failed)
        created_at: Timestamp when scan was created
        started_at: Timestamp when scan started
        completed_at: Timestamp when scan completed
        score: Overall security score (0-100)
        findings: Dictionary of findings by severity
        error: Error message if scan failed
        metadata: Additional metadata about the scan
    """
    
    target: str
    scan_type: str
    id: str = field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:12]}")
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    score: int = 0
    findings: Dict[str, int] = field(default_factory=lambda: {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    })
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate scan data after initialization."""
        self._validate()
    
    def _validate(self):
        """
        Validate scan attributes.
        
        Raises:
            ValueError: If validation fails
        """
        valid_types = ['full', 'quick', 'api', 'headers']
        if self.scan_type not in valid_types:
            raise ValueError(f"Invalid scan type. Must be one of: {valid_types}")
        
        valid_statuses = ['pending', 'running', 'completed', 'failed']
        if self.status not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
        
        if not self.target:
            raise ValueError("Target URL is required")
        
        if self.score < 0 or self.score > 100:
            raise ValueError("Score must be between 0 and 100")
    
    def start(self) -> None:
        """Mark the scan as started."""
        self.status = "running"
        self.started_at = datetime.utcnow()
    
    def complete(self, score: int, findings: Dict[str, int]) -> None:
        """
        Mark the scan as completed.
        
        Args:
            score: Final security score
            findings: Dictionary of findings by severity
        """
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        self.score = score
        self.findings = findings
    
    def fail(self, error_message: str) -> None:
        """
        Mark the scan as failed.
        
        Args:
            error_message: Description of the failure
        """
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        self.error = error_message
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to the scan.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
    
    def get_duration(self) -> Optional[float]:
        """
        Calculate scan duration in seconds.
        
        Returns:
            Duration in seconds, or None if not completed
        """
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.utcnow() - self.started_at).total_seconds()
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert scan to dictionary representation.
        
        Returns:
            Dictionary containing scan data
        """
        data = asdict(self)
        
        # Convert datetime objects to ISO format strings
        if self.created_at:
            data['created_at'] = self.created_at.isoformat() + 'Z'
        if self.started_at:
            data['started_at'] = self.started_at.isoformat() + 'Z'
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat() + 'Z'
        
        # Add duration if available
        duration = self.get_duration()
        if duration is not None:
            data['duration'] = duration
        
        return data
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """
        Convert scan to summary dictionary (for listing).
        
        Returns:
            Dictionary containing summary data
        """
        return {
            'id': self.id,
            'target': self.target,
            'type': self.scan_type,
            'status': self.status,
            'date': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'score': self.score,
            'findings': self.findings
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Scan':
        """
        Create a Scan instance from dictionary data.
        
        Args:
            data: Dictionary containing scan data
        
        Returns:
            Scan instance
        """
        # Convert ISO format strings back to datetime objects
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        if 'started_at' in data and isinstance(data['started_at'], str):
            data['started_at'] = datetime.fromisoformat(data['started_at'].replace('Z', '+00:00'))
        if 'completed_at' in data and isinstance(data['completed_at'], str):
            data['completed_at'] = datetime.fromisoformat(data['completed_at'].replace('Z', '+00:00'))
        
        # Remove any extra fields that aren't part of the dataclass
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        
        return cls(**filtered_data)
    
    def __repr__(self) -> str:
        """String representation of the scan."""
        return f"Scan(id='{self.id}', target='{self.target}', type='{self.scan_type}', status='{self.status}')"
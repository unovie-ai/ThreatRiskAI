"""Models for MITRE data processing."""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class BaseNode:
    """Base class for all MITRE nodes."""
    id: str
    Type: str = "NODE"
    NodeType: str = field(default="")

@dataclass
class BaseRelationship:
    """Base class for all MITRE relationships."""
    id: str
    source_id: str
    target_id: str
    Type: str = "RELATIONSHIP"
    Relationship: str = field(default="")
    description: str = field(default="")
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "Relationship": self.Relationship,
            "SourceID": self.source_id,
            "TargetID": self.target_id,
            "Description": self.description,
            "References": ",".join(self.references)
        }

@dataclass
class AttackPatternNode:
    """Node representing a MITRE attack pattern."""
    id: str
    name: str
    description: str
    Type: str = "NODE"
    NodeType: str = "ATTACK_PATTERN"
    kill_chain_phases: List[Dict[str, str]] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    contributors: List[str] = field(default_factory=list)
    detection: str = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "NodeType": self.NodeType,
            "Name": self.name,
            "Description": self.description,
            "KillChainPhases": ",".join(f"{phase['kill_chain_name']}:{phase['phase_name']}" 
                                      for phase in self.kill_chain_phases),
            "Platforms": ",".join(self.platforms),
            "DataSources": ",".join(self.data_sources),
            "Contributors": ",".join(self.contributors),
            "Detection": self.detection
        }

@dataclass
class ReferenceNode:
    """Node representing a MITRE reference."""
    id: str
    source_name: str
    url: str
    description: str
    Type: str = "NODE"
    NodeType: str = "REFERENCE"
    external_id: str = field(default="")
    reference_type: str = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "NodeType": self.NodeType,
            "SourceName": self.source_name,
            "URL": self.url,
            "Description": self.description,
            "ExternalID": self.external_id,
            "ReferenceType": self.reference_type
        }

@dataclass
class PlatformNode:
    """Node representing a MITRE platform."""
    id: str
    name: str
    Type: str = "NODE"
    NodeType: str = "PLATFORM"
    description: str = field(default="")
    attack_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "NodeType": self.NodeType,
            "Name": self.name,
            "Description": self.description,
            "AttackPatterns": ",".join(self.attack_patterns)
        }

@dataclass
class DetectionNode:
    """Node representing a MITRE detection."""
    id: str
    name: str
    description: str
    Type: str = "NODE"
    NodeType: str = "DETECTION"
    detection_type: str = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "NodeType": self.NodeType,
            "Name": self.name,
            "Description": self.description,
            "DetectionType": self.detection_type
        }

@dataclass
class HasPlatformRelationship:
    """Relationship between attack pattern and platform."""
    id: str
    source_id: str
    target_id: str
    Type: str = "RELATIONSHIP"
    Relationship: str = "HAS_PLATFORM"
    description: str = field(default="")
    references: List[str] = field(default_factory=list)
    platform_type: str = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "Relationship": self.Relationship,
            "SourceID": self.source_id,
            "TargetID": self.target_id,
            "Description": self.description,
            "PlatformType": self.platform_type,
            "References": ",".join(self.references)
        }

@dataclass
class HasReferenceRelationship:
    """Relationship between attack pattern and reference."""
    id: str
    source_id: str
    target_id: str
    Type: str = "RELATIONSHIP"
    Relationship: str = "HAS_REFERENCE"
    description: str = field(default="")
    references: List[str] = field(default_factory=list)
    reference_type: str = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "Relationship": self.Relationship,
            "SourceID": self.source_id,
            "TargetID": self.target_id,
            "Description": self.description,
            "ReferenceType": self.reference_type,
            "References": ",".join(self.references)
        }

@dataclass
class HasDetectionRelationship:
    """Relationship between attack pattern and detection."""
    id: str
    source_id: str
    target_id: str
    Type: str = "RELATIONSHIP"
    Relationship: str = "HAS_DETECTION"
    description: str = field(default="")
    references: List[str] = field(default_factory=list)
    detection_type: str = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary format."""
        return {
            "ID": self.id,
            "Type": self.Type,
            "Relationship": self.Relationship,
            "SourceID": self.source_id,
            "TargetID": self.target_id,
            "Description": self.description,
            "DetectionType": self.detection_type,
            "References": ",".join(self.references)
        } 
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

@dataclass
class BaseNode:
    """Base class for all nodes."""
    id: str
    type: str
    node_type: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.type,
            'Node_Type': self.node_type
        }

@dataclass
class BaseRelationship:
    """Base class for all relationships."""
    id: str
    type: str
    node_type: str
    source_id: str
    target_id: str
    relationship_type: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert relationship to dictionary format."""
        return {
            'ID': self.id,
            'Type': self.type,
            'Node_Type': self.node_type,
            'Source_ID': self.source_id,
            'Target_ID': self.target_id,
            'Relationship_Type': self.relationship_type
        } 
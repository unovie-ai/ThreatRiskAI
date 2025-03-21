from abc import ABC, abstractmethod
from typing import Dict, List, Any

class BaseProcessor(ABC):
    """Base class for all data processors."""
    
    @abstractmethod
    def process(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process the input data and return a list of nodes and relationships.
        
        Args:
            data: The input data to process
            
        Returns:
            List of dictionaries containing node and relationship data
        """
        pass
    
    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the input data.
        
        Args:
            data: The input data to validate
            
        Returns:
            True if data is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def extract_nodes(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract nodes from the input data.
        
        Args:
            data: The input data to process
            
        Returns:
            List of node dictionaries
        """
        pass
    
    @abstractmethod
    def extract_relationships(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract relationships from the input data.
        
        Args:
            data: The input data to process
            
        Returns:
            List of relationship dictionaries
        """
        pass 
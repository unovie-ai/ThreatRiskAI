from typing import Dict, Any
from .base_processor import BaseProcessor
from .cve_processor import CVEProcessor

class ProcessorFactory:
    """Factory class for creating processors."""
    
    _processors: Dict[str, type[BaseProcessor]] = {
        'cve': CVEProcessor,
        # Add more processors here as they are implemented
    }
    
    @classmethod
    def create_processor(cls, processor_type: str) -> BaseProcessor:
        """Create a processor instance based on type.
        
        Args:
            processor_type: Type of processor to create
            
        Returns:
            Processor instance
            
        Raises:
            ValueError: If processor type is not supported
        """
        if processor_type not in cls._processors:
            raise ValueError(f"Unsupported processor type: {processor_type}")
            
        return cls._processors[processor_type]() 
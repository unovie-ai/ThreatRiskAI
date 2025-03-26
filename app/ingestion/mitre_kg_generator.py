"""Knowledge graph generator for MITRE data."""
import json
import logging
import os
from typing import Dict, List, Any, Optional
import networkx as nx
import matplotlib.pyplot as plt
from models.mitre import (
    BaseNode,
    BaseRelationship,
    AttackPatternNode,
    ReferenceNode,
    PlatformNode,
    DetectionNode,
    HasPlatformRelationship,
    HasReferenceRelationship,
    HasDetectionRelationship
)

class MITREKGGenerator:
    """Knowledge graph generator for MITRE data."""
    
    def __init__(self):
        """Initialize the MITRE knowledge graph generator."""
        self.platforms = {}
        self.references = {}
        self.detections = {}
        self.node_counter = 0

    def process(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process MITRE data and generate knowledge graph nodes and relationships.
        
        Args:
            data: Dictionary containing MITRE data
            
        Returns:
            List of dictionaries containing nodes and relationships
        """
        try:
            # Validate input data
            if not self._validate_data(data):
                return []

            # Extract nodes and relationships
            nodes = self._extract_nodes(data)
            relationships = self._extract_relationships(data)

            # Convert to CSV format
            return self._to_csv_format(nodes, relationships)

        except Exception as e:
            logging.error(f"Error processing MITRE data: {str(e)}")
            return []

    def _validate_data(self, data: Dict[str, Any]) -> bool:
        """Validate input data structure.
        
        Args:
            data: Dictionary containing MITRE data
            
        Returns:
            bool: True if data is valid, False otherwise
        """
        if not isinstance(data, dict):
            logging.error("Input data must be a dictionary")
            return False
            
        if "objects" not in data:
            logging.error("Input data must contain 'objects' key")
            return False
            
        if not isinstance(data["objects"], list):
            logging.error("'objects' must be a list")
            return False
            
        return True

    def _generate_node_id(self, prefix: str) -> str:
        """Generate a unique node ID.
        
        Args:
            prefix: Prefix for the node ID
            
        Returns:
            str: Unique node ID
        """
        self.node_counter += 1
        return f"{prefix}_{self.node_counter:08x}"

    def _extract_nodes(self, data: Dict[str, Any]) -> List[BaseNode]:
        """Extract nodes from MITRE data."""
        nodes = []
        
        for obj in data["objects"]:
            if obj["type"] == "attack-pattern":
                # Extract attack pattern node
                attack_pattern = AttackPatternNode(
                    id=obj["id"],
                    name=obj["name"],
                    description=obj["description"],
                    kill_chain_phases=obj.get("kill_chain_phases", []),
                    platforms=obj.get("x_mitre_platforms", []),
                    data_sources=obj.get("x_mitre_data_sources", []),
                    contributors=obj.get("x_mitre_contributors", []),
                    detection=obj.get("x_mitre_detection", "")
                )
                nodes.append(attack_pattern)
                
                # Extract platform nodes
                for platform in obj.get("x_mitre_platforms", []):
                    if platform not in self.platforms:
                        platform_id = f"PLATFORM_{platform.upper()}"
                        platform_node = PlatformNode(
                            id=platform_id,
                            name=platform,
                            description=f"Platform: {platform}",
                            attack_patterns=[obj["id"]]
                        )
                        self.platforms[platform] = platform_node
                        nodes.append(platform_node)
                
                # Extract reference nodes
                for ref in obj.get("external_references", []):
                    ref_id = f"REFERENCE_{len(self.references):08x}"
                    ref_node = ReferenceNode(
                        id=ref_id,
                        source_name=ref.get("source_name", ""),
                        url=ref.get("url", ""),
                        description=ref.get("description", ""),
                        external_id=ref.get("external_id", ""),
                        reference_type=ref.get("source_name", "")
                    )
                    self.references[ref_id] = ref_node
                    nodes.append(ref_node)
                
                # Extract detection node if present
                if obj.get("x_mitre_detection"):
                    detection_id = f"DETECTION_{len(self.detections):08x}"
                    detection_node = DetectionNode(
                        id=detection_id,
                        name=f"Detection for {obj['name']}",
                        description=obj["x_mitre_detection"],
                        detection_type="MITRE"
                    )
                    self.detections[detection_id] = detection_node
                    nodes.append(detection_node)
        
        return nodes

    def _extract_relationships(self, data: Dict[str, Any]) -> List[BaseRelationship]:
        """Extract relationships from MITRE data."""
        relationships = []
        
        for obj in data["objects"]:
            if obj["type"] == "attack-pattern":
                attack_pattern_id = obj["id"]
                
                # Create platform relationships
                for platform in obj.get("x_mitre_platforms", []):
                    if platform in self.platforms:
                        platform_rel = HasPlatformRelationship(
                            id=f"{attack_pattern_id}_HAS_PLATFORM_{self.platforms[platform].id}",
                            source_id=attack_pattern_id,
                            target_id=self.platforms[platform].id,
                            description=f"Attack pattern targets platform {platform}",
                            platform_type=platform
                        )
                        relationships.append(platform_rel)
                
                # Create reference relationships
                for ref in obj.get("external_references", []):
                    ref_id = f"REFERENCE_{len(self.references):08x}"
                    ref_rel = HasReferenceRelationship(
                        id=f"{attack_pattern_id}_HAS_REFERENCE_{ref_id}",
                        source_id=attack_pattern_id,
                        target_id=ref_id,
                        description=f"Attack pattern has reference {ref.get('source_name', '')}",
                        reference_type=ref.get("source_name", "")
                    )
                    relationships.append(ref_rel)
                
                # Create detection relationship if exists
                if obj.get("x_mitre_detection"):
                    detection_id = f"DETECTION_{len(self.detections):08x}"
                    detection_rel = HasDetectionRelationship(
                        id=f"{attack_pattern_id}_HAS_DETECTION_{detection_id}",
                        source_id=attack_pattern_id,
                        target_id=detection_id,
                        description=f"Attack pattern has detection method",
                        detection_type="MITRE"
                    )
                    relationships.append(detection_rel)
            
            elif obj["type"] == "relationship":
                # Handle existing relationships
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                relationship_type = obj.get("relationship_type", "")
                
                if source_ref and target_ref:
                    if relationship_type == "uses":
                        rel = HasReferenceRelationship(
                            id=obj["id"],
                            source_id=source_ref,
                            target_id=target_ref,
                            description=obj.get("description", ""),
                            references=[ref.get("url", "") for ref in obj.get("external_references", [])]
                        )
                    elif relationship_type == "mitigates":
                        rel = HasDetectionRelationship(
                            id=obj["id"],
                            source_id=source_ref,
                            target_id=target_ref,
                            description=obj.get("description", ""),
                            references=[ref.get("url", "") for ref in obj.get("external_references", [])]
                        )
                    else:
                        rel = BaseRelationship(
                            id=obj["id"],
                            source_id=source_ref,
                            target_id=target_ref,
                            Relationship=relationship_type,
                            description=obj.get("description", ""),
                            references=[ref.get("url", "") for ref in obj.get("external_references", [])]
                        )
                    relationships.append(rel)
        
        return relationships

    def _to_csv_format(self, nodes: List[BaseNode], relationships: List[BaseRelationship]) -> List[Dict[str, Any]]:
        """Convert nodes and relationships to CSV format.
        
        Args:
            nodes: List of BaseNode objects
            relationships: List of BaseRelationship objects
            
        Returns:
            List of dictionaries in CSV format
        """
        csv_rows = []
        
        # Add nodes
        for node in nodes:
            csv_rows.append(node.to_dict())
        
        # Add relationships
        for rel in relationships:
            csv_rows.append(rel.to_dict())
        
        return csv_rows

def main():
    """Main function to run the MITRE knowledge graph generator."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate knowledge graph from MITRE data")
    parser.add_argument("input_file", help="Path to input JSON file")
    parser.add_argument("--output_dir", default="knowledge_graphs", help="Output directory for CSV files")
    parser.add_argument("-v", "--visualize", action="store_true", help="Generate visualization")
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Read input file
    with open(args.input_file, 'r') as f:
        data = json.load(f)
    
    # Process data
    generator = MITREKGGenerator()
    processed_data = generator.process(data)
    
    # Save to CSV
    output_file = os.path.join(args.output_dir, f"{os.path.splitext(os.path.basename(args.input_file))[0]}.csv")
    with open(output_file, 'w') as f:
        if processed_data:
            f.write(','.join(processed_data[0].keys()) + '\n')
            for row in processed_data:
                f.write(','.join(str(v) for v in row.values()) + '\n')
    
    print(f"Knowledge graph saved to {output_file}")

if __name__ == "__main__":
    main() 
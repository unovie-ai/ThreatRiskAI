"""CVE processor for extracting nodes and relationships from CVE data."""
import sys
import os
import json
import logging
import networkx as nx
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime

# Add parent directory to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ingestion.base_processor import BaseProcessor
from ingestion.visualization_utils import visualize_knowledge_graph
from models.cve import (
    CVENode,
    ProductNode,
    VendorNode,
    CWENode,
    ReferenceNode,
    EventNode,
    AffectsRelationship,
    BelongsToRelationship,
    HasCWERelationship,
    HasReferenceRelationship,
    HasEventRelationship,
    CPENode,
    HasCPERelationship
)

class CVEProcessor(BaseProcessor):
    """Processor for CVE data."""
    
    def __init__(self):
        """Initialize the processor with counters."""
        # Initialize counters as instance variables
        self.ref_counter = 1
        self.event_counter = 1
        # Track created nodes for relationship building
        self.reference_nodes = {}  # url -> ref_id mapping
        self.event_nodes = {}      # time+value -> event_id mapping
        self.cpe_nodes = set()     # Set of created CPE IDs
        
    def process(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process CVE data and return nodes and relationships.

        Args:
            data: CVE JSON data

        Returns:
            List of dictionaries containing node and relationship data
        """
        if not self.validate(data):
            return []
            
        # Reset counters and tracking for each process call
        self.ref_counter = 1
        self.event_counter = 1
        self.reference_nodes = {}
        self.event_nodes = {}
        self.cpe_nodes = set()
        
        nodes = self.extract_nodes(data)
        relationships = self.extract_relationships(data)
        
        # Convert all objects to dictionaries
        result = []
        for node in nodes:
            result.append(node.to_dict())
        for rel in relationships:
            result.append(rel.to_dict())
            
        return result

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate CVE data format.
        
        Args:
            data: CVE JSON data
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['dataType', 'dataVersion', 'cveMetadata', 'containers']
        return all(field in data for field in required_fields)

    def extract_nodes(self, data: Dict[str, Any]) -> List[Any]:
        """Extract nodes from CVE data."""
        nodes = []
        
        # Extract CVE metadata
        cve_meta = data['cveMetadata']
        cve_id = cve_meta['cveId']
        
        # Get CVE description from CNA container
        cna_container = data['containers']['cna']
        description = next(
            (desc['value'] for desc in cna_container['descriptions'] 
             if desc['lang'] == 'en'),
            ''
        )
        
        # Get CVSS metrics and severity
        cvss_score = 0.0
        cvss_vector = ''
        severity = ''
        impact_confidentiality = ''
        impact_integrity = ''
        impact_availability = ''
        attack_complexity = ''
        attack_vector = ''
        privileges_required = ''
        scope = ''
        user_interaction = ''
        
        # Extract CVSS data
        for metric in cna_container.get('metrics', []):
            if 'cvssV3_1' in metric:
                cvss_data = metric['cvssV3_1']
                cvss_score = float(cvss_data.get('baseScore', 0.0))
                cvss_vector = cvss_data.get('vectorString', '')
                severity = cvss_data.get('baseSeverity', '')
                # Additional CVSS fields
                impact_confidentiality = cvss_data.get('confidentialityImpact', '')
                impact_integrity = cvss_data.get('integrityImpact', '')
                impact_availability = cvss_data.get('availabilityImpact', '')
                attack_complexity = cvss_data.get('attackComplexity', '')
                attack_vector = cvss_data.get('attackVector', '')
                privileges_required = cvss_data.get('privilegesRequired', '')
                scope = cvss_data.get('scope', '')
                user_interaction = cvss_data.get('userInteraction', '')
                break
            elif 'other' in metric and metric['other'].get('type') == 'Red Hat severity rating':
                if not severity:  # Only use Red Hat severity if CVSS severity not found
                    severity = metric['other']['content'].get('value', '')
        
        # Create CVE node with all CVSS metrics
        cve_node = CVENode(
            id=cve_id,
            title=cna_container.get('title', ''),
            description=description,
            published_date=cve_meta.get('datePublished', ''),
            modified_date=cve_meta.get('dateUpdated', ''),
            reserved_date=cve_meta.get('dateReserved', ''),
            state=cve_meta.get('state', ''),
            assigner_id=cve_meta.get('assignerOrgId', ''),
            assigner_name=cve_meta.get('assignerShortName', ''),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            impact_confidentiality=impact_confidentiality,
            impact_integrity=impact_integrity,
            impact_availability=impact_availability,
            attack_complexity=attack_complexity,
            attack_vector=attack_vector,
            privileges_required=privileges_required,
            scope=scope,
            user_interaction=user_interaction
        )
        nodes.append(cve_node)
        
        # Extract affected products and vendors
        for product in cna_container.get('affected', []):
            vendor = product.get('vendor', '')
            product_name = product.get('product', '')
            
            # Get version information
            version_info = product.get('versions', [{}])[0]
            version = version_info.get('version', '')
            status = version_info.get('status', 'unknown')
            
            # Handle version range
            if version == '0' and 'lessThan' in version_info:
                version = f"< {version_info['lessThan']}"
            elif 'lessThan' in version_info:
                version = f"{version} to {version_info['lessThan']}"
            
            # Create product node
            product_node = ProductNode(
                id=f"PRODUCT_{product_name}",
                name=product_name,
                vendor=vendor,
                version=version,
                status=status,
                cpes=product.get('cpes', []),
                platforms=product.get('platforms', []),
                modules=product.get('modules', []),
                program_files=product.get('programFiles', []),
                program_routines=product.get('programRoutines', [])
            )
            nodes.append(product_node)
            
            # Create CPE nodes
            for cpe in product.get('cpes', []):
                cpe_id = f"CPE_{cpe.replace(':', '_')}"
                if cpe_id not in self.cpe_nodes:
                    self.cpe_nodes.add(cpe_id)
                    # Parse CPE string
                    parts = cpe.split(':')[1:]  # Skip 'cpe:' prefix
                    if len(parts) >= 11:  # Ensure we have all components
                        cpe_node = CPENode(
                            id=cpe_id,
                            cpe_string=cpe,
                            part=parts[0],
                            vendor=parts[1],
                            product=parts[2],
                            version=parts[3],
                            update=parts[4],
                            edition=parts[5],
                            language=parts[6],
                            sw_edition=parts[7],
                            target_sw=parts[8],
                            target_hw=parts[9],
                            other=parts[10] if len(parts) > 10 else ''
                        )
                        nodes.append(cpe_node)
            
            # Create vendor node if not exists
            if vendor:
                vendor_node = VendorNode(
                    id=f"VENDOR_{vendor}",
                    name=vendor,
                    industry='Unknown Industry',
                    location='Unknown Location',
                    website='Unknown Website'
                )
                nodes.append(vendor_node)
        
        # Extract problem types (CWE)
        for problem_type in cna_container.get('problemTypes', []):
            for desc in problem_type.get('descriptions', []):
                if desc.get('type') == 'CWE' and desc.get('cweId'):
                    cwe_node = CWENode(
                        id=desc['cweId'],
                        name=desc.get('description', ''),
                        description=desc.get('description', ''),
                        language=desc.get('lang', 'en')
                    )
                    nodes.append(cwe_node)
        
        # Extract references with consistent IDs
        for ref in cna_container.get('references', []):
            url = ref.get('url', '')
            if url:
                ref_id = f"REF_{self.ref_counter}"
                self.reference_nodes[url] = ref_id  # Store mapping for relationships
                self.ref_counter += 1
                
                ref_node = ReferenceNode(
                    id=ref_id,
                    url=url,
                    name=ref.get('name', ''),
                    source=ref.get('tags', [''])[0] if ref.get('tags') else '',
                    reference_tags=ref.get('tags', [])
                )
                nodes.append(ref_node)
        
        # Extract timeline events with consistent IDs
        for event in cna_container.get('timeline', []):
            time = event.get('time', '')
            value = event.get('value', '')
            if time and value:
                event_id = f"EVENT_{self.event_counter}"
                # Store mapping using composite key
                self.event_nodes[f"{time}_{value}"] = event_id
                self.event_counter += 1
                
                event_node = EventNode(
                    id=event_id,
                    time=time,
                    value=value,
                    language=event.get('lang', 'en')
                )
                nodes.append(event_node)
        
        return nodes

    def extract_relationships(self, data: Dict[str, Any]) -> List[Any]:
        """Extract relationships from CVE data."""
        relationships = []
        cna_container = data['containers']['cna']
        cve_id = data['cveMetadata']['cveId']
        
        # Extract CVE-product relationships
        for product in cna_container.get('affected', []):
            product_name = product.get('product', '')
            if product_name:
                version_info = product.get('versions', [{}])[0]
                version = version_info.get('version', '')
                status = version_info.get('status', 'unknown')
                
                # Build version range string
                if version == '0' and 'lessThan' in version_info:
                    version_range = f"< {version_info['lessThan']}"
                elif 'lessThan' in version_info:
                    version_range = f"{version} to {version_info['lessThan']}"
                else:
                    version_range = version
                
                # Get attack vector from CVSS if available
                attack_vector = 'network'  # Default
                for metric in cna_container.get('metrics', []):
                    if 'cvssV3_1' in metric:
                        attack_vector = metric['cvssV3_1'].get('attackVector', '').lower() or attack_vector
                        break
                
                affects_rel = AffectsRelationship(
                    id=f"CVE_{cve_id}_AFFECTS_PRODUCT_{product_name}",
                    source_id=cve_id,
                    target_id=f"PRODUCT_{product_name}",
                    version_range=version_range,
                    attack_vector=attack_vector,
                    cve_status=status,
                    patch_status='unpatched' if status == 'affected' else 'patched'
                )
                relationships.append(affects_rel)
                
                # Create vendor-product relationship
                vendor = product.get('vendor', '')
                if vendor:
                    belongs_to_rel = BelongsToRelationship(
                        id=f"PRODUCT_{product_name}_BELONGS_TO_VENDOR_{vendor}",
                        source_id=f"PRODUCT_{product_name}",
                        target_id=f"VENDOR_{vendor}",
                        license='unknown',
                        support_status='unknown'
                    )
                    relationships.append(belongs_to_rel)
                
                # Create product-CPE relationships
                for cpe in product.get('cpes', []):
                    cpe_id = f"CPE_{cpe.replace(':', '_')}"
                    if cpe_id in self.cpe_nodes:  # Only create relationship if CPE node exists
                        has_cpe_rel = HasCPERelationship(
                            id=f"PRODUCT_{product_name}_HAS_CPE_{cpe.replace(':', '_')}",
                            source_id=f"PRODUCT_{product_name}",
                            target_id=cpe_id
                        )
                        relationships.append(has_cpe_rel)
        
        # Extract CVE-CWE relationships
        for problem_type in cna_container.get('problemTypes', []):
            for desc in problem_type.get('descriptions', []):
                if desc.get('type') == 'CWE' and desc.get('cweId'):
                    has_cwe_rel = HasCWERelationship(
                        id=f"CVE_{cve_id}_HAS_CWE_{desc['cweId']}",
                        source_id=cve_id,
                        target_id=desc['cweId']
                    )
                    relationships.append(has_cwe_rel)
        
        # Extract CVE-reference relationships using stored reference IDs
        for ref in cna_container.get('references', []):
            url = ref.get('url', '')
            if url and url in self.reference_nodes:
                ref_id = self.reference_nodes[url]
                has_ref_rel = HasReferenceRelationship(
                    id=f"CVE_{cve_id}_HAS_REFERENCE_{ref_id}",
                    source_id=cve_id,
                    target_id=ref_id
                )
                relationships.append(has_ref_rel)
        
        # Extract CVE-event relationships using stored event IDs
        for event in cna_container.get('timeline', []):
            time = event.get('time', '')
            value = event.get('value', '')
            event_key = f"{time}_{value}"
            if event_key in self.event_nodes:
                event_id = self.event_nodes[event_key]
                has_event_rel = HasEventRelationship(
                    id=f"CVE_{cve_id}_HAS_EVENT_{event_id}",
                    source_id=cve_id,
                    target_id=event_id
                )
                relationships.append(has_event_rel)
        
        return relationships

def main():
    """Main entry point for running the processor directly."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Process CVE data.')
    parser.add_argument('input_file', help='Path to input JSON file')
    parser.add_argument('platform', help='Target platform')
    parser.add_argument('--output_dir', default='output', help='Output directory')
    parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    
    args = parser.parse_args()

    processor = CVEProcessor()
    
    with open(args.input_file, 'r') as f:
        data = json.load(f)
    
    processed_data = processor.process(data)
    
    # Save processed data
    os.makedirs(args.output_dir, exist_ok=True)
    output_base = os.path.join(args.output_dir, os.path.splitext(os.path.basename(args.input_file))[0])
    
    # Save as CSV
    csv_path = f"{output_base}.csv"
    with open(csv_path, 'w') as f:
        if processed_data:
            f.write(','.join(processed_data[0].keys()) + '\n')
            for row in processed_data:
                f.write(','.join(str(v) for v in row.values()) + '\n')
    
    print(f"Processed data saved to {csv_path}")
    
    # Create and visualize knowledge graph if requested
    if args.visualize:
        # Create NetworkX graph from processed data
        G = nx.DiGraph()
        
        # Add nodes and edges from processed data
        for item in processed_data:
            if item.get('Type') == 'NODE':
                G.add_node(item['id'], **{k: v for k, v in item.items() if k != 'id'})
            elif item.get('Type') == 'RELATIONSHIP':
                G.add_edge(
                    item['source_id'],
                    item['target_id'],
                    **{k: v for k, v in item.items() if k not in ['source_id', 'target_id']}
                )
        
        # Generate visualizations
        visualize_knowledge_graph(G, output_base)
        print(f"Visualizations generated in {os.path.dirname(output_base)}")

if __name__ == '__main__':
    main()

import argparse
import hashlib
import uuid
import json
import logging
import os
import re
import networkx as nx
import matplotlib.pyplot as plt
from typing import Optional, List

# Validation helpers
def validate_mitre_id(mitre_id: str) -> bool:
    """Validate MITRE ATT&CK ID format."""
    return bool(re.match(r'^attack-pattern--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', mitre_id))

def normalize_label(label: str) -> str:
    """Clean and normalize labels for consistency."""
    if not label:
        return "MISSING_LABEL"
    return re.sub(r'\s+', ' ', label.strip()).title()

def get_normalized_vendor(vendor: Optional[str], product: str) -> str:
    """Derive vendor from product name if not provided."""
    if vendor and vendor.strip():
        return normalize_label(vendor)
    # Try to extract vendor from product name (e.g. "Microsoft Word" -> "Microsoft")
    return normalize_label(product.split()[0]) if product else "UNKNOWN_VENDOR"

def normalize_platform(platform: str) -> str:
    """Standardize platform names."""
    platform = platform.lower().strip()
    if platform in ['win', 'windows']:
        return "Windows"
    elif platform in ['linux', 'gnu/linux']:
        return "Linux"
    elif platform in ['container', 'docker', 'kubernetes']:
        return "Containers"
    return platform.title() if platform else "Cross-Platform"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SUPPORTED_DATA_TYPES = ["cve", "mitre"]
# Constants for directory paths
KNOWLEDGE_GRAPHS_DIR = "knowledge_graphs"
VISUALIZATION_DIR = os.path.join(KNOWLEDGE_GRAPHS_DIR, "visualization")
CYTOSCAPE_DIR = os.path.join(VISUALIZATION_DIR, "cytoscape")


def create_knowledge_graph(json_file_path, data_type, args):
    """
    Creates a knowledge graph from a JSON file.

    Args:
        json_file_path (str): The path to the JSON file.
        data_type (str): Type of data (cve or mitre).

    Returns:
        networkx.Graph: The knowledge graph.
    """
    if data_type == "cve":
        return create_cve_knowledge_graph(json_file_path, args)
    elif data_type == "mitre":
        return create_mitre_knowledge_graph(json_file_path, args)
    else:
        logging.error(f"Unsupported data type: {data_type}")
        return None


def create_cve_knowledge_graph(json_file_path, args):
    """
    Creates a knowledge graph from a CVE JSON file.

    Args:
        json_file_path (str): The path to the JSON file.

    Returns:
        networkx.Graph: The knowledge graph.
    """
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {json_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in: {json_file_path}")
        return None

    G = nx.DiGraph()

    # Extract CVE node and relationships
    extract_cve_nodes(G, data)
    extract_cve_relationships(G, data)

    return G


def extract_cve_nodes(graph, data):
    """
    Extracts CVE, Product, and Vendor nodes from the CVE data and adds them to the graph.

    Args:
        graph (networkx.Graph): The knowledge graph.
        data (dict): The CVE data in JSON format.
    """
    # Extract and validate CVE ID
    cve_metadata = data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId")
    if not cve_id:
        logging.error("Missing CVE ID in metadata")
        return

    # Add central CVE node with structured attributes
    cve_node_id = cve_id  # Use CVE ID as the node ID
    severity = cve_metadata.get("severity", "Unknown")
    published = cve_metadata.get("datePublished", "")
    modified = cve_metadata.get("dateUpdated", "")
    source = "NVD"

    description = f"CVE {cve_id} is a vulnerability with severity {severity}, published on {published}, and last modified on {modified}. Source: {source}."

    graph.add_node(cve_node_id,
                   Type="CVE",
                   Label=f"CVE-{cve_id}",
                   Description=description)

    # Extract affected products and add them as nodes
    affected_products = data.get("containers", {}).get("cna", {}).get("affected", [])
    for product in affected_products:
        product_name = product.get("product")
        if not product_name:
            continue

        # Validate and normalize product/vendor information
        vendor = get_normalized_vendor(product.get("vendor"), product_name)
        product_name = normalize_label(product_name)
        version = product.get("version") or "unversioned"

        # Only add nodes if we have valid identifiers
        if not vendor or not product_name:
            logging.warning(f"Skipping invalid product entry in CVE {cve_id}")
            continue

        # Add vendor node with enriched data
        vendor_node_id = f"VENDOR_{vendor}"  # Use vendor name as node ID
        industry = product.get("industry", "Unknown Industry")
        vendor_location = product.get("vendor_location", "Unknown Location")
        vendor_website = product.get("vendor_website", "Unknown Website")

        vendor_description = f"Vendor {vendor} is in the {industry} industry, located in {vendor_location}, with website {vendor_website}."

        graph.add_node(vendor_node_id,
                      Type="Vendor",
                      Label=vendor,
                      Description=vendor_description)

        # Add product node with validated attributes
        product_node_id = f"PRODUCT_{product_name}"  # Use product name as node ID
        platform = normalize_platform(product.get("platform", "Unknown Platform"))
        eol = product.get("end_of_life", "Unknown EOL")
        update_channel = product.get("update_channel", "Unknown Update Channel")

        product_description = f"Product {product_name} is made by {vendor}, version {version}, runs on {platform}, has EOL {eol}, and update channel {update_channel}."

        graph.add_node(product_node_id,
                      Type="Product",
                      Label=product_name,
                      Description=product_description)


def extract_cve_relationships(graph, data):
    """
    Extracts relationships between CVEs, Products, and Vendors from the CVE data and adds them to the graph.

    Args:
        graph (networkx.Graph): The knowledge graph.
        data (dict): The CVE data in JSON format.
    """
    # Extract and validate CVE ID
    cve_metadata = data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId")
    if not cve_id:
        logging.error("Missing CVE ID in metadata")
        return

    # Extract affected products and add them as nodes
    affected_products = data.get("containers", {}).get("cna", {}).get("affected", [])
    for product in affected_products:
        product_name = product.get("product")
        if not product_name:
            continue

        # Validate and normalize product/vendor information
        vendor = get_normalized_vendor(product.get("vendor"), product_name)
        product_name = normalize_label(product_name)

        # Add product node with version info
        version = product.get("version", "Unknown Version")
        attack_vector = product.get("attackVector", "network")
        cve_status = product.get("status", "confirmed")
        patch_status = product.get("patch", "unpatched")

        # Add validated relationships only if both nodes exist
        product_node_id = f"PRODUCT_{product_name}"
        vendor_node_id = f"VENDOR_{vendor}"

        if graph.has_node(cve_id) and graph.has_node(product_node_id):
            edge_id = f"CVE_{cve_id}_AFFECTS_PRODUCT_{product_name}"
            relationship_description = f"CVE {cve_id} affects product {product_name}, version range {version}, attack vector {attack_vector}, CVE status {cve_status}, and patch status {patch_status}."
            graph.add_edge(cve_id, product_node_id,
                          id=edge_id,
                          Relationship=relationship_description,
                          Type="AFFECTS")

        # Add vendor relationship with additional metadata
        if graph.has_node(product_node_id) and graph.has_node(vendor_node_id):
            vendor_edge_id = f"PRODUCT_{product_name}_BELONGS_TO_VENDOR_{vendor}"
            license_info = product.get("license", "unknown")
            support_status = product.get("support_status", "unknown")
            vendor_relationship_description = f"Product {product_name} belongs to vendor {vendor}, with license {license_info} and support status {support_status}."

            graph.add_edge(product_node_id, vendor_node_id,
                          id=vendor_edge_id,
                          Relationship=vendor_relationship_description,
                          Type="BELONGS_TO")

    # Extract descriptions and add them as nodes
    descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for description in descriptions:
        description_text = description.get("value", "No Description")
        if description_text and description_text.strip():
            # Create consistent description node ID using SHA256 hash
            description_hash = hashlib.sha256(description_text.encode()).hexdigest()[:16]
            description_node_id = f"DESC_{description_hash}"
            
            # Add/update description node with full text
            if not graph.has_node(description_node_id):
                graph.add_node(description_node_id, 
                             Type="Description",
                             Label=description_text[:50] + "...",  # Truncated label
                             FullText=description_text,  # Store full description
                             Description=f"Description of CVE {cve_id}")
            
            # Create relationship edge with context
            edge_id = f"CVE_{cve_id}_DESCRIBES_{description_hash}"
            graph.add_edge(cve_id, description_node_id, 
                          id=edge_id, 
                          relation="describes", 
                          Type="DESCRIBES",
                          Context="CVE Description",
                          Source="NVD")
        else:
            logging.warning(f"Empty description for CVE {cve_id}. Skipping description node creation.")


def create_mitre_knowledge_graph(json_file_path, args):
    """
    Creates a knowledge graph from a MITRE ATT&CK JSON file.

    Args:
        json_file_path (str): The path to the JSON file.

    Returns:
        networkx.Graph: The knowledge graph.
    """
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {json_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in: {json_file_path}")
        return None

    G = nx.DiGraph()

    # Extract objects and filter for attack-patterns
    objects = data.get("objects", [])
    attack_patterns = [obj for obj in objects if obj.get("type") == "attack-pattern"]

    # Process each attack-pattern object
    for attack_pattern in attack_patterns:
        mitre_id = attack_pattern.get("id")

        # Skip non-relevant objects
        if not mitre_id or not mitre_id.startswith("attack-pattern--"):
            logging.warning(f"Skipping object with invalid MITRE ID: {mitre_id}")
            continue

        # Validate MITRE ID format and content
        if not validate_mitre_id(mitre_id) or not attack_pattern.get("name"):
            logging.warning(f"Skipping invalid MITRE entry: {mitre_id}")
            continue
            
        tactic_names = [t.capitalize() for t in attack_pattern.get("x_mitre_tactic", [])]
        platforms = [normalize_platform(p) for p in attack_pattern.get("x_mitre_platforms", [])]
        
        # Add MITRE technique node
        technique_name = attack_pattern["name"]
        G.add_node(mitre_id,
                  Type="Technique",
                  Label=technique_name,
                  Tactic=tactic_names,
                  Platform=platforms,
                  Version=attack_pattern.get("x_mitre_version", "1.0"),
                  Source="MITRE ATT&CK",
                  Description=attack_pattern.get("description", ""),
                  Detection=attack_pattern.get("x_mitre_detection", ""))
        
        # Add platform relationships
        for platform in platforms:
            platform_id = f"PLATFORM_{platform.upper().replace(' ', '_')}"
            G.add_node(platform_id,
                      Type="Platform",
                      Label=platform,
                      Category="Security Platform")
            G.add_edge(mitre_id, platform_id, 
                      Relationship="TARGETS",
                      Confidence="High",
                      Evidence=attack_pattern.get("x_mitre_platforms", []))

        # Link techniques to their tactics with additional metadata
        for tactic in tactic_names:
            tactic_id = f"TACTIC_{tactic.upper().replace(' ', '_')}"
            if not G.has_node(tactic_id):
                G.add_node(tactic_id, 
                          Type="Tactic",
                          Label=tactic,
                          Framework="ATT&CK",
                          Description=f"MITRE ATT&CK {tactic} Tactic")
            G.add_edge(mitre_id, tactic_id, 
                      Relationship="EMPLOYS",
                      Phase=attack_pattern.get("kill_chain_phases", [{}])[0].get("phase_name", ""),
                      Technique_Type="Primary")

        # Add mitigation relationships
        for mitigation in attack_pattern.get("x_mitre_mitigation", []):
            mitigation_id = f"MITIGATION_{uuid.uuid4().hex[:8]}"
            G.add_node(mitigation_id,
                      Type="Mitigation",
                      Label=mitigation.get("name", "Unnamed Mitigation"),
                      Description=mitigation.get("description", ""),
                      Source=mitigation.get("source", "MITRE"))
            G.add_edge(mitre_id, mitigation_id,
                      Relationship="MITIGATED_BY",
                      Effectiveness=mitigation.get("effectiveness", "Unknown"))

        # Add reference URLs and external links
        if "external_references" in attack_pattern:
            for ref in attack_pattern["external_references"]:
                if ref.get("url"):
                    ref_id = f"REFERENCE_{uuid.uuid4().hex[:8]}"
                    G.add_node(ref_id,
                             Type="Reference",
                             Label=ref.get("source_name", "Reference"),
                             URL=ref["url"],
                             Description=f"External reference for {technique_name}")
                    G.add_edge(mitre_id, ref_id,
                             Relationship="HAS_REFERENCE",
                             Reference_Type=ref.get("source_name", "Generic"))

        # Process relationships with other techniques
        for rel in [obj for obj in objects if obj.get("source_ref") == mitre_id]:
            target_tech = next((t for t in objects if t["id"] == rel["target_ref"]), None)
            if target_tech and target_tech.get("type") == "attack-pattern":
                rel_type = rel.get("relationship_type", "RELATED_TO").replace("-", "_").upper()
                G.add_edge(mitre_id, target_tech["id"],
                           Relationship=rel_type,
                           Description=rel.get("description", ""),
                           Source="MITRE Relationship")

        # Add detection information
        if "x_mitre_detection" in attack_pattern:
            detection_id = f"DETECTION_{uuid.uuid4().hex[:8]}"
            G.add_node(detection_id,
                      Type="Detection",
                      Label="Detection Logic",
                      Description=attack_pattern["x_mitre_detection"],
                      Confidence="Medium")
            G.add_edge(mitre_id, detection_id,
                      Relationship="HAS_DETECTION",
                      Data_Sources=attack_pattern.get("x_mitre_data_sources", []))

    return G


def add_technique_and_subtechniques(graph, parent_id, technique, objects):
    """
    Recursively adds a technique and its sub-techniques to the knowledge graph.

    Args:
        graph (networkx.Graph): The knowledge graph.
        parent_id (str): The ID of the parent node (MITRE ID or parent technique).
        technique (dict): The technique data.
        objects (list): List of all objects in the MITRE ATT&CK data.
    """
    technique_id = technique.get("id")
    technique_name = technique.get("name", "Unknown Technique")

    # Add technique with validation
    if not technique_id or not technique_id.startswith("attack-pattern--"):
        logging.warning(f"Skipping invalid technique ID: {technique_id}")
        return

    technique_node_id = technique_id  # Use technique_id as node ID
    description = technique.get("description", "")
    kill_chain = technique.get("kill_chain_phases", [])

    technique_description = f"Technique {technique_name} (ID: {technique_id}) is a MITRE ATT&CK technique with description: {description} and kill chain phases: {kill_chain}."

    if not graph.has_node(technique_node_id):
        graph.add_node(technique_node_id,
                       Type="Technique",
                       Label=technique_name,
                       Description=technique_description)

    edge_id = f"TECHNIQUE_{parent_id}_CONTAINS_TECHNIQUE_{technique_name}"
    relationship_description = f"{parent_id} contains technique {technique_name}."
    if graph.has_node(parent_id) and graph.has_node(technique_node_id):
        graph.add_edge(parent_id, technique_node_id,
                       id=edge_id,
                       Relationship=relationship_description,
                       Type="CONTAINS",
                       Subtype="Subtechnique" if "subtechnique" in technique_id else "Primary",
                       Mitigation=technique.get("x_mitre_mitigation", ""))

    # Find sub-techniques
    sub_techniques_relationships = [obj for obj in objects if obj.get("type") == "relationship" and obj.get("source_ref") == technique_id and obj.get("relationship_type") == "subtechnique-of"]
    for relationship in sub_techniques_relationships:
        sub_technique_id = relationship.get("target_ref")
        sub_technique = next((obj for obj in objects if obj.get("id") == sub_technique_id), None)
        if sub_technique:
            add_technique_and_subtechniques(graph, technique_node_id, sub_technique, objects)


def save_knowledge_graph(graph, base_filename):
    """
    Saves the knowledge graph in GML format and a combined CSV format.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the graph.
    """
    # Save as GML
    gml_path = f"{base_filename}.gml"
    nx.write_gml(graph, gml_path)
    logging.info(f"Knowledge graph saved as GML: {gml_path}")

    # Save as combined CSV
    combined_path = f"{base_filename}.csv"
    with open(combined_path, "w") as f:
        # Write header
        f.write("ID,Text\n")

        # Write nodes with special handling for descriptions
        for node_id, attributes in graph.nodes(data=True):
            if attributes.get('Type') == 'Description':
                # For descriptions, use the full text stored in FullText attribute
                text = attributes.get('FullText', attributes.get('Description', 'No description'))
            else:
                node_type = attributes.get('Type', 'unknown')
                description = attributes.get('Description', 'No description')
                text = f"{node_type}: {description}"
            
            # Escape quotes and newlines for CSV
            text = text.replace('"', '""').replace('\n', ' ')
            f.write(f'"{node_id}","{text}"\n')

        # Write edges
        for source, target, data in graph.edges(data=True):
            edge_id = data.get('id')
            relationship = data.get('Relationship', 'No relationship')
            edge_type = data.get('Type', 'Unknown')
            if not edge_id:
                logging.warning(f"Missing edge ID between {source} and {target}. Generating one.")
                edge_id = f"{source}_relates_to_{target}".replace(" ", "_")  # Generate a unique ID
            f.write(f'"{edge_id}","{relationship} ({edge_type})"\n')

    logging.info(f"Combined knowledge graph data saved as CSV: {combined_path}")


def visualize_knowledge_graph(graph, base_filename):
    """
    Generates a visualization of the knowledge graph in PNG format.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the visualization.
    """
    plt.figure(figsize=(16, 12), dpi=300)

    # Use spring layout for directed graphs
    pos = nx.spring_layout(graph, seed=42)  # Seed for reproducibility

    # Node styling based on type
    node_colors = []
    for node in graph.nodes(data=True):
        if node[1].get('Type') == 'CVE':
            node_colors.append('#ff6961')  # Red
        elif node[1].get('Type') == 'Product':
            node_colors.append('#77dd77')  # Green
        else:  # MITRE/Technique
            node_colors.append('#84b6f4')  # Blue

    # Edge styling based on relationship
    edge_colors = []
    for edge in graph.edges(data=True):
        if edge[2].get('Relationship') == 'AFFECTS':
            edge_colors.append('#ff0000')  # Red
        else:  # CONTAINS or other
            edge_colors.append('#0000ff')  # Blue

    nx.draw(graph, pos, with_labels=True, 
            node_color=node_colors, 
            edge_color=edge_colors,
            node_size=[len(str(n))*200 for n in graph.nodes()], 
            font_size=8, 
            font_weight="bold",
            arrows=True,
            arrowsize=20,
            connectionstyle='arc3,rad=0.1')
    plt.title("Knowledge Graph Visualization")

    png_path = f"{base_filename}.png"
    plt.savefig(png_path)
    plt.close()  # Close the plot to free memory

    # Generate Cytoscape visualization
    cytoscape_html_path = os.path.join(CYTOSCAPE_DIR, f"{base_filename.split('/')[-1]}.html")
    generate_cytoscape_html(graph, cytoscape_html_path)


def generate_cytoscape_html(graph, output_path):
    """
    Generates an HTML file with a Cytoscape.js visualization of the knowledge graph.

    Args:
        graph (networkx.Graph): The knowledge graph.
        output_path (str): The output path for the HTML file.
    """
    os.makedirs(CYTOSCAPE_DIR, exist_ok=True)

    # Prepare nodes and edges for Cytoscape.js
    nodes = [{"data": {"id": node_id, "label": data.get("Label", node_id), "type": data.get("Type", "Unknown")}} for node_id, data in graph.nodes(data=True)]
    edges = [{"data": {"source": source, "target": target, "label": data.get("Relationship", "Connects")}} for source, target, data in graph.edges(data=True)]

    # Cytoscape.js stylesheet
    stylesheet = [
        {
            "selector": "node",
            "style": {
                "label": "data(label)",
                "font-size": "12px",
                "text-valign": "center",
                "text-halign": "center",
                "background-color": "white",
                "border-color": "black",
                "border-width": "1px",
                "padding": "5px"
            }
        },
        {
            "selector": "edge",
            "style": {
                "width": 2,
                "line-color": "#ccc",
                "target-arrow-color": "#ccc",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "label": "data(label)",
                "font-size": "10px"
            }
        },
        {
            "selector": "node[type='CVE']",
            "style": {
                "background-color": "#ff6961",
                "color": "white"
            }
        },
        {
            "selector": "node[type='Product']",
            "style": {
                "background-color": "#77dd77",
                "color": "black"
            }
        },
        {
            "selector": "node[type='MITRE']",
            "style": {
                "background-color": "#84b6f4",
                "color": "black"
            }
        }
    ]

    # HTML content with Cytoscape.js
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Knowledge Graph Visualization</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.21.0/cytoscape.min.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            #cy {{
                width: 100%;
                height: 800px;
                display: block;
            }}
        </style>
    </head>
    <body>
        <h1>Knowledge Graph Visualization</h1>
        <div id="cy"></div>
        <script>
            var cy = cytoscape({{
                container: document.getElementById('cy'),
                elements: {{
                    nodes: {nodes},
                    edges: {edges}
                }},
                style: {stylesheet},
                layout: {{
                    name: 'cose',  // Use cose layout
                    nodeRepulsion: 400000,
                    idealEdgeLength: 100,
                    edgeElasticity: 100,
                    gravity: 50,
                    randomize: true,
                    animate: false,
                    
                }}
            }});
        </script>
    </body>
    </html>
    """

    # Write HTML content to file
    with open(output_path, "w") as f:
        f.write(html_content)

    logging.info(f"Cytoscape.js visualization saved as HTML: {output_path}")


def main():
    """
    Main function to orchestrate the knowledge graph generation and visualization.
    """
    parser = argparse.ArgumentParser(description="Generate knowledge graphs from JSON files.")
    parser.add_argument("json_file_path", help="Path to the input JSON file")
    parser.add_argument("data_type", help="Type of data (cve or mitre)")
    args = parser.parse_args()

    # Validate data_type
    if args.data_type not in SUPPORTED_DATA_TYPES:
        logging.error(f"Invalid data type: {args.data_type}. Supported types are: {SUPPORTED_DATA_TYPES}")
        return

    # Extract filename from path
    file_name = os.path.splitext(os.path.basename(args.json_file_path))[0]

    # Create the knowledge graphs and visualization directories if they don't exist
    os.makedirs(KNOWLEDGE_GRAPHS_DIR, exist_ok=True)
    os.makedirs(VISUALIZATION_DIR, exist_ok=True)

    # Create the knowledge graph
    graph = create_knowledge_graph(args.json_file_path, args.data_type, args)
    if graph is None:
        logging.error("Failed to create knowledge graph.")
        return

    num_nodes = graph.number_of_nodes()
    num_edges = graph.number_of_edges()

    logging.info(f"Knowledge graph contains {num_nodes} nodes and {num_edges} edges.")

    # Save the knowledge graph
    base_filename = os.path.join(KNOWLEDGE_GRAPHS_DIR, file_name)
    save_knowledge_graph(graph, base_filename)

    # Visualize the knowledge graph
    visualization_filename = os.path.join(VISUALIZATION_DIR, file_name)
    visualize_knowledge_graph(graph, visualization_filename)

    print("Knowledge graph generation and visualization completed.")


if __name__ == "__main__":
    main()

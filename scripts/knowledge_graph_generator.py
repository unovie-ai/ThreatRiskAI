import argparse
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


def create_knowledge_graph(json_file_path, data_type):
    """
    Creates a knowledge graph from a JSON file.

    Args:
        json_file_path (str): The path to the JSON file.
        data_type (str): Type of data (cve or mitre).

    Returns:
        networkx.Graph: The knowledge graph.
    """
    if data_type == "cve":
        return create_cve_knowledge_graph(json_file_path)
    elif data_type == "mitre":
        return create_mitre_knowledge_graph(json_file_path)
    else:
        logging.error(f"Unsupported data type: {data_type}")
        return None


def create_cve_knowledge_graph(json_file_path):
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
    graph.add_node(cve_id,
                   Type="CVE",
                   Label=f"CVE-{cve_id}",
                   Severity=cve_metadata.get("severity", "Unknown"),
                   Published=cve_metadata.get("datePublished", ""),
                   Modified=cve_metadata.get("dateUpdated", ""),
                   Source="NVD")

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
        graph.add_node(vendor, 
                      Type="Vendor",
                      Label=vendor,
                      Industry=product.get("industry", ""),
                      Location=product.get("vendor_location", ""))
        
        # Add product node with validated attributes
        graph.add_node(product_name,
                      Type="Product",
                      Label=product_name,
                      Vendor=vendor,
                      Version=version,
                      Platform=normalize_platform(product.get("platform", "")),
                      EOL=product.get("end_of_life", ""),
                      UpdateChannel=product.get("update_channel", ""))


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

        # Add product node with version info
        vendor = product.get("vendor", "Unknown Vendor")
        version = product.get("version", "Unknown Version")

        # Add validated relationships only if both nodes exist
        if graph.has_node(cve_id) and graph.has_node(product_name):
            edge_id = f"{cve_id}_AFFECTS_{product_name}"
            graph.add_edge(cve_id, product_name,
                          id=edge_id,
                          Relationship="AFFECTS",
                          VersionRange=version,
                          AttackVector=product.get("attackVector", "network"),
                          CVEStatus=product.get("status", "confirmed"),
                          PatchStatus=product.get("patch", "unpatched"))

            # Add vendor relationship with additional metadata
            if graph.has_node(vendor):
                vendor_edge_id = f"{product_name}_BELONGS_TO_{vendor}"
                graph.add_edge(product_name, vendor,
                              id=vendor_edge_id,
                              Relationship="BELONGS_TO",
                              License=product.get("license", "unknown"),
                              SupportStatus=product.get("support_status", "unknown"))

    # Extract descriptions and add them as nodes
    descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for description in descriptions:
        description_text = description.get("value", "No Description")
        graph.add_node(description_text, type="description", **description)
        graph.add_edge(cve_id, description_text, relation="describes")


def create_mitre_knowledge_graph(json_file_path):
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
        
        # Link techniques to their tactics
        for tactic in tactic_names:
            tactic_id = f"tactic_{tactic.lower().replace(' ', '_')}"
            G.add_node(tactic_id, 
                      Type="Tactic",
                      Label=tactic,
                      Framework="ATT&CK")
            G.add_edge(mitre_id, tactic_id, Relationship="EMPLOYS")

        # Extract techniques and add them as nodes
        techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"]
        for technique in techniques:
            add_technique_and_subtechniques(G, mitre_id, technique, objects)

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
        
    graph.add_node(technique_name,
                   Type="Technique",
                   Label=technique.get("name", "Unknown Technique"),
                   ID=technique_id,
                   Description=technique.get("description", ""),
                   KillChain=technique.get("kill_chain_phases", []))

    edge_id = f"{parent_id}_CONTAINS_{technique_name}"
    graph.add_edge(parent_id, technique_name,
                   id=edge_id,
                   Relationship="CONTAINS",
                   Subtype="Subtechnique" if "subtechnique" in technique_id else "Primary",
                   Mitigation=technique.get("x_mitre_mitigation", ""))

    # Find sub-techniques
    sub_techniques_relationships = [obj for obj in objects if obj.get("type") == "relationship" and obj.get("source_ref") == technique_id and obj.get("relationship_type") == "subtechnique-of"]
    for relationship in sub_techniques_relationships:
        sub_technique_id = relationship.get("target_ref")
        sub_technique = next((obj for obj in objects if obj.get("id") == sub_technique_id), None)
        if sub_technique:
            add_technique_and_subtechniques(graph, technique_name, sub_technique, objects)


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
        f.write("Node_ID,Node_Type,Attributes,Source_Node_ID,Target_Node_ID,Edge_Type\n")

        # Write nodes
        for node_id, attributes in graph.nodes(data=True):
            node_type = attributes.get('type', 'unknown')
            attr_str = str({k: v for k, v in attributes.items() if k != 'type'})
            f.write(f'"{node_id}","{node_type}","{attr_str}",,,,\n')

        # Write edges
        for source, target, data in graph.edges(data=True):
            edge_id = data.get('id')
            edge_type = data.get('relation', 'unknown')
            if not edge_id:
                logging.warning(f"Missing edge ID between {source} and {target}. Generating one.")
                edge_id = f"{source}_relates_to_{target}"  # Generate a unique ID
            f.write(f'"{edge_id}",,,{source},{target},{edge_type}\n')

    # Validate that there are no blank IDs in the first column
    with open(combined_path, "r") as f:
        for line in f:
            if line.startswith(","):
                logging.error(f"Found line with missing ID: {line.strip()}")

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
    graph = create_knowledge_graph(args.json_file_path, args.data_type)
    if graph is None:
        logging.error("Failed to create knowledge graph.")
        return

    # Save the knowledge graph
    base_filename = os.path.join(KNOWLEDGE_GRAPHS_DIR, file_name)
    save_knowledge_graph(graph, base_filename)

    # Visualize the knowledge graph
    visualization_filename = os.path.join(VISUALIZATION_DIR, file_name)
    visualize_knowledge_graph(graph, visualization_filename)

    print("Knowledge graph generation and visualization completed.")


if __name__ == "__main__":
    main()

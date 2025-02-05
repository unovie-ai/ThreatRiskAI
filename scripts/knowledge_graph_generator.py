import argparse
import json
import logging
import os
import networkx as nx
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SUPPORTED_DATA_TYPES = ["cve", "mitre"]
# Constants for directory paths
KNOWLEDGE_GRAPHS_DIR = "knowledge_graphs"
VISUALIZATION_DIR = os.path.join(KNOWLEDGE_GRAPHS_DIR, "visualization")


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
    
    # Extract and validate CVE ID
    cve_metadata = data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId")
    if not cve_id:
        logging.error("Missing CVE ID in metadata")
        return None
        
    # Add central CVE node with structured attributes
    G.add_node(cve_id, 
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
            
        # Add product node with version info
        vendor = product.get("vendor", "Unknown Vendor")
        version = product.get("version", "Unknown Version")
        G.add_node(product_name,
                   Type="Product",
                   Label=f"{vendor} {product_name}",
                   Vendor=vendor,
                   Version=version,
                   Platform=product.get("platform", ""))
        
        # Add versioned edge with CVE relationship
        G.add_edge(cve_id, product_name, 
                   Relationship="AFFECTS",
                   VersionRange=version,
                   AttackVector=product.get("attackVector", ""))

    # Extract descriptions and add them as nodes
    descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for description in descriptions:
        description_text = description.get("value", "No Description")
        G.add_node(description_text, type="description", **description)
        G.add_edge(cve_id, description_text, relation="describes")

    return G


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

    # Validate MITRE ID format
    mitre_id = data.get("id")
    if not mitre_id or not mitre_id.startswith("attack-pattern--"):
        logging.error(f"Invalid MITRE ID format: {mitre_id}")
        return None
        
    # Add MITRE node with structured attributes
    G.add_node(mitre_id,
               Type="MITRE",
               Label=data.get("name", "Unknown Technique"),
               Tactic=data.get("x_mitre_tactic", []),
               Platform=data.get("x_mitre_platforms", []),
               Version=data.get("x_mitre_version", ""),
               Source="MITRE ATT&CK")

    # Extract techniques and add them as nodes
    objects = data.get("objects", [])
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
                   
    graph.add_edge(parent_id, technique_name,
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
            edge_type = data.get('relation', 'unknown')
            f.write(f',,,{source},{target},{edge_type}\n')
    
    logging.info(f"Combined knowledge graph data saved as CSV: {combined_path}")


def visualize_knowledge_graph(graph, base_filename):
    """
    Generates a visualization of the knowledge graph in PNG format.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the visualization.
    """
    plt.figure(figsize=(16, 12), dpi=300)
    
    # Create layered layout for directed graphs
    pos = nx.drawing.layout.planar_layout(graph)
    
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
    logging.info(f"Knowledge graph visualization saved as PNG: {png_path}")


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

import argparse
import json
import logging
import os
import networkx as nx
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for directory paths
KNOWLEDGE_GRAPHS_DIR = "knowledge_graphs"
VISUALIZATION_DIR = os.path.join(KNOWLEDGE_GRAPHS_DIR, "visualization")


def create_knowledge_graph(json_file_path):
    """
    Creates a knowledge graph from a JSON file.

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

    G = nx.Graph()

    # Extract CVE ID as the central node
    cve_id = data.get("cveMetadata", {}).get("cveId", "Unknown CVE")
    G.add_node(cve_id, type="cve", **data.get("cveMetadata", {}))

    # Extract affected products and add them as nodes
    affected_products = data.get("containers", {}).get("cna", {}).get("affected", [])
    for product in affected_products:
        product_name = product.get("product", "Unknown Product")
        G.add_node(product_name, type="product", **product)
        G.add_edge(cve_id, product_name, relation="affects")

    # Extract descriptions and add them as nodes
    descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for description in descriptions:
        description_text = description.get("value", "No Description")
        G.add_node(description_text, type="description", **description)
        G.add_edge(cve_id, description_text, relation="describes")

    return G


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
    plt.figure(figsize=(12, 12))
    pos = nx.spring_layout(graph, seed=42)  # Layout algorithm

    nx.draw(graph, pos, with_labels=True, node_color="skyblue", node_size=1500, font_size=10, font_weight="bold")
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
    args = parser.parse_args()

    # Extract filename from path
    file_name = os.path.splitext(os.path.basename(args.json_file_path))[0]

    # Create the knowledge graphs and visualization directories if they don't exist
    os.makedirs(KNOWLEDGE_GRAPHS_DIR, exist_ok=True)
    os.makedirs(VISUALIZATION_DIR, exist_ok=True)

    # Create the knowledge graph
    graph = create_knowledge_graph(args.json_file_path)
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

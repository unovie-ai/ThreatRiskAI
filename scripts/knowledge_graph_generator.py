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

    # Example: Assuming the JSON structure has a list of objects with 'id' and 'related_to' fields
    # Modify this part based on your actual JSON structure
    for item in data.get("objects", []):
        node_id = item.get("id")
        if node_id:
            G.add_node(node_id, **item)  # Add node attributes from the item

            # Add edges based on 'related_to' field (if it exists)
            related_to = item.get("related_to")
            if related_to:
                if isinstance(related_to, list):
                    for target_id in related_to:
                        G.add_edge(node_id, target_id)
                else:
                    G.add_edge(node_id, related_to)

    return G


def save_knowledge_graph(graph, base_filename):
    """
    Saves the knowledge graph in GML and CSV formats.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the graph.
    """
    # Save as GML
    gml_path = f"{base_filename}.gml"
    nx.write_gml(graph, gml_path)
    logging.info(f"Knowledge graph saved as GML: {gml_path}")

    # Save as CSV (nodes and edges)
    nodes_path = f"{base_filename}_nodes.csv"
    edges_path = f"{base_filename}_edges.csv"

    # Save nodes with attributes
    with open(nodes_path, "w") as f:
        f.write("id," + ",".join(list(graph.nodes[next(iter(graph.nodes()))].keys())) + "\n")  # Header
        for node_id, attributes in graph.nodes(data=True):
            f.write(str(node_id) + "," + ",".join(str(value) for value in attributes.values()) + "\n")
    logging.info(f"Knowledge graph nodes saved as CSV: {nodes_path}")

    # Save edges
    with open(edges_path, "w") as f:
        f.write("source,target\n")  # Header
        for source, target in graph.edges():
            f.write(f"{source},{target}\n")
    logging.info(f"Knowledge graph edges saved as CSV: {edges_path}")


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

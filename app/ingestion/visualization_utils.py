"""Visualization utilities for knowledge graphs."""
import os
import logging
import networkx as nx
import matplotlib.pyplot as plt

# Constants for directory paths
KNOWLEDGE_GRAPHS_DIR = "knowledge_graphs"
VISUALIZATION_DIR = os.path.join(KNOWLEDGE_GRAPHS_DIR, "visualization")
CYTOSCAPE_DIR = os.path.join(VISUALIZATION_DIR, "cytoscape")

def save_knowledge_graph_gml(graph, base_filename):
    """
    Saves the knowledge graph in GML format.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the graph.
    """
    os.makedirs(KNOWLEDGE_GRAPHS_DIR, exist_ok=True)
    gml_path = f"{base_filename}.gml"
    nx.write_gml(graph, gml_path)
    logging.info(f"Knowledge graph saved as GML: {gml_path}")

def save_knowledge_graph_csv(graph, base_filename):
    """
    Saves the knowledge graph in CSV format.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the graph.
    """
    os.makedirs(KNOWLEDGE_GRAPHS_DIR, exist_ok=True)
    csv_path = f"{base_filename}.csv"
    
    with open(csv_path, "w") as f:
        # Write header
        f.write("ID,Type,NodeType,Title,Description,Properties\n")
        
        # Write nodes
        for node_id, attrs in graph.nodes(data=True):
            node_type = attrs.get('Type', 'Unknown')
            title = attrs.get('Label', node_id)
            description = attrs.get('Description', '')
            # Convert remaining attributes to string
            properties = "|".join(f"{k}={v}" for k, v in attrs.items() 
                                if k not in ['Type', 'Label', 'Description'])
            
            # Escape CSV special characters
            description = description.replace('"', '""').replace('\n', ' ')
            f.write(f'"{node_id}",NODE,{node_type},"{title}","{description}","{properties}"\n')
        
        # Write relationships
        for source, target, attrs in graph.edges(data=True):
            rel_type = attrs.get('Type', 'RELATED_TO')
            rel_id = attrs.get('id', f"{source}_{rel_type}_{target}")
            description = attrs.get('Description', '')
            properties = "|".join(f"{k}={v}" for k, v in attrs.items() 
                                if k not in ['Type', 'Description'])
            
            description = description.replace('"', '""').replace('\n', ' ')
            f.write(f'"{rel_id}",RELATIONSHIP,{rel_type},{source},{target},"{properties}"\n')
    
    logging.info(f"Knowledge graph saved as CSV: {csv_path}")

def generate_cytoscape_html(graph, base_filename):
    """
    Generates an HTML file with a Cytoscape.js visualization of the knowledge graph.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving the visualization.
    """
    os.makedirs(CYTOSCAPE_DIR, exist_ok=True)
    output_path = os.path.join(CYTOSCAPE_DIR, f"{os.path.basename(base_filename)}.html")

    # Prepare nodes and edges for Cytoscape.js
    nodes = []
    for node_id, attrs in graph.nodes(data=True):
        node_type = attrs.get('Type', 'Unknown')
        label = attrs.get('Label', node_id)
        nodes.append({
            "data": {
                "id": node_id,
                "label": label,
                "type": node_type,
                "description": attrs.get('Description', '')
            }
        })

    edges = []
    for source, target, attrs in graph.edges(data=True):
        edges.append({
            "data": {
                "source": source,
                "target": target,
                "label": attrs.get('Type', 'RELATED_TO'),
                "description": attrs.get('Description', '')
            }
        })

    # Cytoscape.js stylesheet
    stylesheet = [
        {
            "selector": "node",
            "style": {
                "label": "data(label)",
                "font-size": "12px",
                "text-valign": "center",
                "text-halign": "center",
                "background-color": "#666",
                "color": "#fff",
                "border-width": "1px",
                "border-color": "#000",
                "width": "60px",
                "height": "60px"
            }
        },
        {
            "selector": "edge",
            "style": {
                "label": "data(label)",
                "font-size": "10px",
                "text-rotation": "autorotate",
                "text-margin-y": "-10px",
                "curve-style": "bezier",
                "target-arrow-shape": "triangle",
                "width": "2px",
                "line-color": "#666",
                "target-arrow-color": "#666"
            }
        },
        # Node type-specific styles
        {
            "selector": "node[type = 'CVE']",
            "style": {
                "background-color": "#ff4444",
                "shape": "rectangle"
            }
        },
        {
            "selector": "node[type = 'Product']",
            "style": {
                "background-color": "#44ff44",
                "shape": "ellipse"
            }
        },
        {
            "selector": "node[type = 'Vendor']",
            "style": {
                "background-color": "#4444ff",
                "shape": "diamond"
            }
        },
        {
            "selector": "node[type = 'CWE']",
            "style": {
                "background-color": "#ffff44",
                "shape": "hexagon"
            }
        }
    ]

    # HTML template
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Knowledge Graph Visualization</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.21.0/cytoscape.min.js"></script>
        <style>
            body {{ margin: 0; font-family: Arial, sans-serif; }}
            #cy {{ 
                width: 100vw; 
                height: 100vh; 
                position: absolute; 
                top: 0; 
                left: 0; 
            }}
            #info-panel {{
                position: fixed;
                top: 10px;
                right: 10px;
                background: white;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 5px;
                max-width: 300px;
                display: none;
            }}
        </style>
    </head>
    <body>
        <div id="cy"></div>
        <div id="info-panel"></div>
        <script>
            var cy = cytoscape({{
                container: document.getElementById('cy'),
                elements: {{
                    nodes: {nodes},
                    edges: {edges}
                }},
                style: {stylesheet},
                layout: {{
                    name: 'cose',
                    idealEdgeLength: 100,
                    nodeOverlap: 20,
                    refresh: 20,
                    fit: true,
                    padding: 30,
                    randomize: false,
                    componentSpacing: 100,
                    nodeRepulsion: 400000,
                    edgeElasticity: 100,
                    nestingFactor: 5,
                    gravity: 80,
                    numIter: 1000,
                    initialTemp: 200,
                    coolingFactor: 0.95,
                    minTemp: 1.0
                }}
            }});

            // Show node/edge information on hover
            const infoPanel = document.getElementById('info-panel');
            cy.on('mouseover', 'node, edge', function(e) {{
                const ele = e.target;
                infoPanel.innerHTML = `
                    <h3>${{ele.data('label')}}</h3>
                    <p><strong>Type:</strong> ${{ele.data('type') || ele.data('label')}}</p>
                    <p><strong>Description:</strong> ${{ele.data('description') || 'No description'}}</p>
                `;
                infoPanel.style.display = 'block';
            }});

            cy.on('mouseout', 'node, edge', function() {{
                infoPanel.style.display = 'none';
            }});
        </script>
    </body>
    </html>
    """

    with open(output_path, "w") as f:
        f.write(html_content)

    logging.info(f"Cytoscape visualization saved as HTML: {output_path}")

def visualize_knowledge_graph(graph, base_filename):
    """
    Generates all visualizations for the knowledge graph.

    Args:
        graph (networkx.Graph): The knowledge graph.
        base_filename (str): The base filename for saving visualizations.
    """
    # Create directories if they don't exist
    os.makedirs(VISUALIZATION_DIR, exist_ok=True)
    os.makedirs(CYTOSCAPE_DIR, exist_ok=True)

    # Save as GML
    save_knowledge_graph_gml(graph, base_filename)

    # Save as CSV
    save_knowledge_graph_csv(graph, base_filename)

    # Generate Cytoscape visualization
    generate_cytoscape_html(graph, base_filename)

    # Generate static visualization using matplotlib
    plt.figure(figsize=(16, 12))
    pos = nx.spring_layout(graph, k=1, iterations=50)
    
    # Draw nodes with different colors based on type
    node_colors = []
    for node in graph.nodes(data=True):
        node_type = node[1].get('Type', 'Unknown')
        if node_type == 'CVE':
            node_colors.append('#ff4444')
        elif node_type == 'Product':
            node_colors.append('#44ff44')
        elif node_type == 'Vendor':
            node_colors.append('#4444ff')
        elif node_type == 'CWE':
            node_colors.append('#ffff44')
        else:
            node_colors.append('#666666')

    nx.draw(graph, pos,
            node_color=node_colors,
            with_labels=True,
            node_size=1000,
            font_size=8,
            font_weight='bold',
            arrows=True,
            edge_color='#666666',
            arrowsize=20)

    plt.title("Knowledge Graph Visualization")
    plt.savefig(f"{base_filename}.png", dpi=300, bbox_inches='tight')
    plt.close()

    logging.info(f"Static visualization saved as PNG: {base_filename}.png") 
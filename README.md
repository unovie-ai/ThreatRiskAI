# ThreatRiskAI
Threat Risk Assessment for SBOM using GENAI

## Project Goals

*   Develop a system to ingest and process threat intelligence data from various sources (CVE, MITRE ATT&CK).
*   Generate knowledge graphs representing threat relationships and platform-specific vulnerabilities.
*   Utilize Generative AI to query and analyze the knowledge graphs for threat risk assessment.
*   Provide a user-friendly interface for uploading data, querying the knowledge base, and visualizing results.

## Project Objectives

*   Ingest and process CVE and MITRE ATT&CK data in JSON format.
*   Create a knowledge graph database to store threat intelligence data.
*   Implement a query interface to retrieve relevant threat information.
*   Develop a visualization tool to display the knowledge graph and relationships.
*   Integrate a Generative AI model to answer complex threat-related questions.

## Project Structure

```
.
├── LICENSE
├── README.md
├── app
│   ├── Dockerfile
│   ├── __pycache__
│   │   └── config.cpython-311.pyc
│   ├── app.py
│   ├── config.py
│   ├── inference
│   │   ├── __init__.py
│   │   └── query_databases.py
│   ├── ingestion
│   │   ├── __init__.py
│   │   ├── cve_processor.py
│   │   ├── db_updater.py
│   │   ├── db_updater_row.py
│   │   ├── knowledge_graph_generator.py
│   │   └── mitre_processor.py
│   ├── main.py
│   ├── models.py
│   ├── requirements.txt
│   ├── scripts                # Python Scripts.
│   │   └── process_directory.sh
│   └── swagger.yml
├── data                        # RAW JSON files for (CVE/MITRE)
│   ├── db                      # Stores threats.db (Flat Database)
│   ├── knowledge_graphs        # Knowledge Graphs
│   │   └── visualization
│   │       └── cytoscape
│   ├── output
│   └── uploads
├── docker
│   └── docker-compose.yml
└── docs
    └── curl-cmds.md
```

Example .env file:
```
LLM_MODEL=gemini-2.0-flash-exp
NUM_RESULTS=10
DATABASES=db/threats.db:threats
EMBEDDING_MODEL=jina-embeddings-v2-small-en
```

## Docker Instructions

1.  **Build the Docker image:**

    ```bash
    docker build -t threatriskaiapp .
    ```

2.  **Run the Docker container:**

    ```bash
    docker run -d -p 8000:8000 --env-file .env threatriskaiapp
    ```

    *   Replace `.env` with the path to your environment variables file if it's located elsewhere.
    *   This command maps port 8000 of the container to port 8000 on your host machine.

## Usage

### Processing Data and Generating Knowledge Graphs

To process a directory of CVE or MITRE data and generate knowledge graphs, use the
`scripts/process_directory.sh` script:

```bash
./scripts/process_directory.sh /path/to/data CVE containers
```

This command will process all JSON files in `/path/to/data` as CVE data, filtering for the "containers"
platform. The knowledge graphs will be generated in the `knowledge_graphs` directory.

### Creating Embeddings and Storing in Database

To create embeddings of the knowledge graphs in CSV format and store them in a database, use the
`main.py` script with the `--embed` and `--kg-directory` options:

```bash
python main.py CVE containers --embed --kg-directory knowledge_graphs
```

This command will create embeddings for the CVE data, filtering for the "containers" platform, using the
knowledge graphs located in the `knowledge_graphs` directory. The embeddings will be stored in a
database named `cve.db`.

### Querying the API

After running the application, you can query the API using tools like `curl` or `Postman`.  Example:

```bash
curl -X GET "http://localhost:8000/query?query=what are the cves related to containers?"
```

This will query the threat intelligence database for CVEs related to containers.  The API will return a JSON response with the results.

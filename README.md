# ThreatRiskAI
Threat Risk Assessment for SBOM using GENAI

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

## Usage

To process a directory of CVE or MITRE data and generate knowledge graphs, use the 
`scripts/process_directory.sh` script:

```bash
./scripts/process_directory.sh /path/to/data CVE containers
```

This command will process all JSON files in `/path/to/data` as CVE data, filtering for the "containers" 
platform. The knowledge graphs will be generated in the `knowledge_graphs` directory.

To create embeddings of the knowledge graphs in CSV format and store them in a database, use the 
`main.py` script with the `--embed` and `--kg-directory` options:

```bash
python main.py CVE containers --embed --kg-directory knowledge_graphs
```

This command will create embeddings for the CVE data, filtering for the "containers" platform, using the
knowledge graphs located in the `knowledge_graphs` directory. The embeddings will be stored in a 
database named `cve.db`.

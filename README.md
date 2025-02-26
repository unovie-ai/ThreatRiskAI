# ThreatRiskAI
Threat Risk Assessment for SBOM using GENAI

## Project Structure

```
│── /data                   # Raw JSON files (CVE, MITRE, etc.)
│── /knowledge_graphs        # Stores CSV files of extracted knowledge graphs
│── /knowledge_graphs/visualization  # Stores HTML visualizations
│── /db                     # Stores threats.db (Flat database)
│── /scripts                 # Python scripts (modular but final output will be single program)
│── .env                     # API keys, configurations (LLM model, number of results, database configurations)
│── requirements.txt         # Dependencies
│── main.py                  # Final executable Python program
│── README.md
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

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
```

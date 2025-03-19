curl -X POST -F "data_type=CVE" -F "platform=containers" -F "file=@/home/seq_rakesh/Downloads/cve_main/all_containers/CVE-2024-53844.json" http://localhost:8000/upload

Ingest (Embedding) 

curl -X POST -H "Content-Type: application/json" -d '{"data_type": "CVE", "platform": "containers", "kg_directory": "knowledge_graphs"}' http://localhost:8000/embed

Inference - 

curl "http://localhost:8000/query?query=What%20is%20E.D.D.I"



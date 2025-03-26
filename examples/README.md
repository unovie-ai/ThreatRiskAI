# Examples

This directory contains example JSON files for CVE and MITRE data that can be used with the Threat Intelligence API.

## Usage

These examples are designed to be used with the API endpoints described below. For all examples, we will be using `containers` as the platform.

### Upload Endpoint

The upload endpoint allows you to upload a JSON file for processing.

**Endpoint:** `/upload`

**Method:** POST

**Example `curl` request:**

```bash
curl -X POST \
  http://localhost:8000/upload \
  -H 'Content-Type: multipart/form-data' \
  -F data_type=cve \
  -F platform=containers \
  -F file=@cve/CVE-2024-47616.json
```

   or

```bash
curl -X POST \
  http://localhost:8000/upload \
  -H 'Content-Type: multipart/form-data' \
  -F data_type=mitre \
  -F platform=containers \
  -F file=@mitre/enterprise-attack-16.1.json
```

### Embed Endpoint

The embed endpoint allows you to embed the knowledge graph into the database.

**Endpoint:** `/embed`

**Method:** POST

**Example `curl` request:**

```bash
curl -X POST \
  http://localhost:8000/embed \
  -H 'Content-Type: application/json' \
  -d '{
    "data_type": "cve",
    "platform": "containers"
  }'
```

   or

```bash
curl -X POST \
  http://localhost:8000/embed \
  -H 'Content-Type: application/json' \
  -d '{
    "data_type": "mitre",
    "platform": "containers"
  }'
```

### Query Endpoint

The query endpoint allows you to query the threat intelligence database.

**Endpoint:** `/query`

**Method:** GET

**Example `curl` request:**

```bash
curl http://localhost:8000/query?query="What are the vulnerabilities associated with containers?"
```

## Swagger Documentation

You can access the Swagger documentation for the API at:

http://localhost:8000/docs
```

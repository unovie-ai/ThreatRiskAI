# Project Capabilities

This document outlines the core capabilities of the Threat Intelligence project, focusing on data ingestion, processing, knowledge graph generation, and database interaction based on the code in `app/ingestion`, `app/models`, and `app/schemas`.

## 1. Data Ingestion and Processing

The system is designed to ingest and process threat intelligence data from standard formats.

### 1.1. CVE Processing (`app/ingestion/cve_processor.py`)

*   **Input:** Takes CVE data in JSON format (following the CVE JSON 5.0 standard).
*   **Validation:** Performs basic validation to ensure required fields are present.
*   **Extraction:** Extracts detailed information to create various node types:
    *   `CVENode`: Core vulnerability details, including CVSS metrics (v3.1), severity, dates, assigner info.
    *   `ProductNode`: Affected products, including vendor, version, status, CPEs, platforms.
    *   `VendorNode`: Information about the product vendor.
    *   `CPENode`: Detailed CPE information parsed from CPE strings.
    *   `CWENode`: Associated Common Weakness Enumerations (CWEs).
    *   `ReferenceNode`: External references (URLs, names, tags).
    *   `EventNode`: Timeline events related to the CVE.
*   **Relationship Extraction:** Identifies and creates relationships between nodes:
    *   `AffectsRelationship` (CVE -> Product)
    *   `BelongsToRelationship` (Product -> Vendor)
    *   `HasCPERelationship` (Product -> CPE)
    *   `HasCWERelationship` (CVE -> CWE)
    *   `HasReferenceRelationship` (CVE -> Reference)
    *   `HasEventRelationship` (CVE -> Event)
*   **Output:** Produces a list of dictionaries representing the extracted nodes and relationships, ready for CSV conversion or further processing.

### 1.2. MITRE ATT&CK Processing (`app/ingestion/mitre_processor.py`)

*   **Input:** Takes MITRE ATT&CK data in STIX 2.x JSON format (e.g., `enterprise-attack.json`).
*   **Platform Filtering:** Filters `attack-pattern` objects based on a specified target platform (e.g., "containers", "windows", "linux") by checking the `x_mitre_platforms` field. Uses a mapping (`PLATFORM_MAPPING`) for broader matching (e.g., "containers" matches "docker", "kubernetes").
*   **Output:** Generates individual JSON files for each filtered `attack-pattern` and its directly related objects (identified via `*_ref` fields). Outputs a JSON list containing the paths to these generated files.

## 2. Knowledge Graph Generation

The processed data is transformed into a knowledge graph structure.

### 2.1. Data Models (`app/models/`)

*   **Structured Representation:** Uses Python dataclasses (`cve.py`, `mitre.py`) to define the structure of nodes and relationships for both CVE and MITRE data.
*   **Attributes:** Models capture detailed attributes for each entity (e.g., CVSS scores for CVEs, kill chain phases for Attack Patterns).
*   **Serialization:** Includes `to_dict()` methods in models for easy conversion into a dictionary format, suitable for CSV generation and database storage.

### 2.2. CSV Output

*   **CVE:** The `CVEProcessor` output is directly convertible to CSV format, where each row represents a node or a relationship dictionary.
*   **MITRE:** The `MITREKGGenerator` (`app/ingestion/mitre_kg_generator.py`) processes the filtered MITRE JSON files (output from `mitre_processor.py`) to extract nodes (AttackPattern, Reference, Platform, Detection) and relationships (HasPlatform, HasReference, HasDetection, Uses, Mitigates) and saves them into CSV files.
*   **Format:** The CSV files typically contain columns representing the attributes defined in the data models.

## 3. Database Embedding

The generated knowledge graph data is embedded into vector databases for similarity searching.

### 3.1. LLM Integration (`app/ingestion/db_updater.py`, `app/ingestion/db_updater_row.py`)

*   **Tooling:** Leverages the `llm` command-line tool for generating embeddings.
*   **Models:** Configurable embedding model (defaults to `jina-embeddings-v2-small-en`, specified via `EMBEDDING_MODEL` environment variable).
*   **Embedding Methods:**
    *   `db_updater.py`: Uses `llm embed-multi` to embed multiple CSV files from a directory efficiently.
    *   `db_updater_row.py`: Uses `llm embed` to process a single CSV file row by row, suitable for large files or when fine-grained control/retry logic is needed. Includes content length checks and retry mechanisms.

### 3.2. SQLite Storage

*   **Database:** Stores embeddings in SQLite databases (`db/cve.db`, `db/mitre.db`).
*   **Collections:** Organizes embeddings within databases into collections named after the target platform (e.g., "containers", "windows"). This allows querying specific subsets of data.
*   **Management:** Scripts handle database and collection creation, checking for existing data to prevent redundant embedding.

## 4. API Schemas (`app/schemas/`)

*   **Validation:** Uses Pydantic models to define and validate the structure of data for API interactions.
*   **Models:**
    *   `QueryRequestSchema`: Defines the expected format for query requests.
    *   `QueryResponseSchema`: Defines the structure for successful query responses.
    *   `ErrorResponseSchema`: Defines the format for returning error messages.

## 5. Visualization (Optional)

*   **Utilities:** Provides tools (`app/ingestion/visualization_utils.py`, `app/ingestion/knowledge_graph_generator.py`) to visualize the generated knowledge graphs.
*   **Formats:**
    *   Static PNG images using Matplotlib.
    *   Interactive HTML files using Cytoscape.js.
    *   Graph Modeling Language (GML) files.
*   **Purpose:** Aids in understanding the structure and relationships within the threat intelligence data.

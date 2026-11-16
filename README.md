# Windows Memory Forensics Analyzer

A Windows memory forensics and anomaly detection application powered by Volatility 3, Python, and FastAPI.

## Overview

This project aims to develop a web-based tool for analyzing Windows memory images, identifying suspicious activities, and supporting digital forensic investigations.

The application integrates Volatility 3 with a FastAPI backend to manage investigation cases, extract forensic artifacts, store analysis results, and maintain analysis execution history.

The project is intended for educational and digital forensics research, with rule-based anomaly detection, a web dashboard, and forensic reporting planned for future development.

## Tech Stack

- **Python** – Core programming language
- **FastAPI** – REST API backend
- **Uvicorn** – ASGI web server
- **Volatility 3** – Memory forensics framework
- **SQLite** – Database for cases, analysis history, and forensic evidence

## Implemented Features

### Backend & Case Management

- REST API backend using FastAPI
- SQLite database initialization
- Investigation case creation and retrieval
- Automatic API documentation with Swagger UI
- Input validation and basic API error handling

### Memory Image Management

- Memory image registration and validation
- Support for `.raw`, `.mem`, and `.vmem` file extensions
- SHA-256 hash calculation
- Memory image metadata storage and retrieval
- Association of memory images with investigation cases
- Local memory image path validation

### Volatility 3 Integration

- Automated memory analysis using Volatility 3
- Selection among six supported plugins through the REST API
- JSON analysis results returned by FastAPI
- Analysis execution history stored in SQLite
- Analysis status tracking (`running`, `completed`, `failed`)
- Analysis timeout and error handling
- Plugin allowlisting to restrict supported operations

### Windows System & Process Analysis

- `windows.info` – Extract Windows kernel and operating system information
- `windows.pslist` – Enumerate Windows processes
- `windows.pstree` – Analyze parent-child process relationships
- `windows.cmdline` – Extract process command-line arguments
- Retrieve process information including PID, PPID, process names, and creation times

### Memory & Network Analysis

- `windows.malfind` – Identify memory regions with potentially suspicious characteristics
- `windows.netscan` – Extract network connections and socket information
- Retrieve memory region details, including process identifiers, memory protections, and address ranges
- Retrieve network artifacts, including IP addresses, ports, protocols, connection states, and associated processes

### Forensic Evidence Management

- Automatic storage of Volatility 3 analysis results in SQLite
- JSON-based forensic evidence storage
- Association of evidence records with analysis runs
- Evidence record indexing and counting
- Retrieval of previously stored analysis results through REST API
- Review of stored evidence without rerunning Volatility 3

## Planned Features

### Rule-Based Anomaly Detection

- Detect suspicious parent-child process relationships
- Identify suspicious process command-line patterns
- Assess potentially malicious memory regions
- Identify suspicious network connection indicators
- Generate investigation findings and severity levels
- Associate detection findings with supporting evidence

### Evidence Search & Traceability

- Search and filter stored forensic evidence
- Browse evidence across investigation cases
- Improve evidence provenance and review workflows

### Web Interface & Reporting

- Interactive web dashboard
- Investigation case management interface
- Memory image selection and analysis interface
- Process tree visualization
- Network connection visualization
- Security findings and evidence dashboard
- Analysis history visualization
- Forensic report generation and export

### Testing & Evaluation

- Prepare labeled Windows memory images
- Evaluate detection rules using forensic datasets
- Measure detection performance and false positives
- Evaluate Precision, Recall, and F1-score
- Document experimental results and limitations

## Project Structure

```text
Windows-Memory-Forensics-Analyzer/
├── project/
│   └── backend/
│       ├── main.py
│       ├── database.py
│       ├── volatility_runner.py
│       └── evidence_storage.py
├── samples/              # Local memory images (not tracked)
├── data/                 # Local SQLite database (not tracked)
├── requirements.txt
├── .gitignore
└── README.md
```

Memory images, local databases, and Python virtual environments are excluded from Git version control.

The `samples` and `data` directories are used locally and may not appear in a freshly cloned repository.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/LaRemontada12/Windows-Memory-Forensics-Analyzer.git
cd Windows-Memory-Forensics-Analyzer
```

### 2. Create a Python Virtual Environment

```powershell
python -m venv .venv
```

### 3. Install Dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Prepare Memory Images

Create a local directory for Windows memory images:

```powershell
New-Item -ItemType Directory -Force samples
```

Place supported Windows memory images inside the `samples` directory.

Memory images are not included in this repository.

## Run Backend

Start the FastAPI server:

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --app-dir project/backend --reload
```

Open the automatically generated API documentation:

http://127.0.0.1:8000/docs

## Available API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Application information |
| GET | `/health` | Backend health check |
| POST | `/cases` | Create an investigation case |
| GET | `/cases` | Retrieve investigation cases |
| POST | `/cases/{case_id}/images` | Register a memory image |
| GET | `/cases/{case_id}/images` | Retrieve registered memory images |
| POST | `/images/{image_id}/analyze` | Analyze a memory image using a selected Volatility 3 plugin and store its evidence |
| GET | `/analysis-runs/{run_id}/evidence` | Retrieve previously stored forensic evidence |

### Supported Analysis Plugins

The analysis API currently supports six Volatility 3 plugins:

| Plugin | Description |
|---|---|
| `windows.info` | Windows system information |
| `windows.pslist` | Process enumeration |
| `windows.pstree` | Parent-child process relationships |
| `windows.cmdline` | Process command-line extraction |
| `windows.malfind` | Potentially suspicious memory regions |
| `windows.netscan` | Network connection and socket artifacts |

The plugin can be selected using the optional `plugin` query parameter.

By default, the API executes `windows.info`.

### Example Analysis Request

```http
POST /images/1/analyze?plugin=windows.pslist
```

Example response structure (shortened):

```json
{
  "run_id": 8,
  "image_id": 1,
  "plugin": "windows.pslist",
  "status": "completed",
  "evidence_count": 139,
  "results": [
    {
      "PID": 4,
      "ImageFileName": "System"
    }
  ]
}
```

The example above illustrates a shortened response structure.

Actual analysis results depend on the selected memory image and plugin.

### Example Evidence Retrieval

```http
GET /analysis-runs/8/evidence
```

Example response structure (shortened):

```json
{
  "run_id": 8,
  "image_id": 1,
  "plugin": "windows.pslist",
  "status": "completed",
  "evidence_count": 139,
  "evidence": [
    {
      "record_index": 0,
      "data": {
        "PID": 4,
        "ImageFileName": "System"
      }
    }
  ]
}
```

The example shows the structure of stored forensic evidence.

The complete response contains all evidence records associated with the selected analysis run.

Previously stored evidence can be retrieved without executing Volatility 3 again.

## Current Limitations

- Memory image registration currently uses local file paths inside the `samples` directory.
- File extension validation does not guarantee that a file contains a valid Windows memory image.
- Automated analysis currently supports six Volatility 3 plugins.
- Analysis execution history and forensic evidence are stored in SQLite.
- Evidence retrieval currently uses analysis run IDs; advanced searching and filtering have not yet been implemented.
- Analysis runs created before evidence storage was implemented do not automatically contain stored evidence.
- Automated anomaly detection and severity classification have not yet been implemented.
- A dedicated web dashboard and forensic reporting system are not yet available.
- The current Volatility runner uses a Windows-specific executable path.
- The current implementation is intended for local development and testing.

## Project Status

**Under active development.**

The following components have been implemented and tested:

- FastAPI backend and SQLite database
- Investigation case management
- Memory image registration and validation
- SHA-256 integrity hashing
- Automated Volatility 3 analysis
- Integration of six Windows memory analysis plugins
- Windows process enumeration and process tree analysis
- Process command-line extraction
- Potentially suspicious memory region extraction
- Network connection and socket artifact extraction
- Analysis execution history and status tracking
- Automatic forensic evidence storage
- JSON-based evidence persistence in SQLite
- Forensic evidence retrieval through REST API

Future development will focus on rule-based anomaly detection, investigation findings management, an interactive web dashboard, and forensic reporting.

## Disclaimer

This project is intended for educational and digital forensic research purposes.

Memory analysis results and suspicious indicators require further verification by a forensic analyst.

The presence of potentially suspicious memory regions or network artifacts does not necessarily indicate malware or malicious activity.

Only analyze memory images obtained and used with appropriate authorization.
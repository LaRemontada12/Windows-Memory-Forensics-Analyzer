# Windows Memory Forensics Analyzer

A Windows memory forensics and anomaly detection application powered by Volatility 3, Python, and FastAPI.

## Overview

This project aims to develop a web-based tool for analyzing Windows memory images, identifying suspicious activities, and supporting digital forensic investigations.

The application integrates Volatility 3 with a FastAPI backend to automate memory analysis, manage investigation cases, extract forensic artifacts, and maintain analysis execution history.

The project is being developed as an educational and research-oriented digital forensics tool, with future support for rule-based anomaly detection and forensic reporting.

## Tech Stack

- **Python** – Core programming language
- **FastAPI** – REST API backend
- **Uvicorn** – ASGI web server
- **Volatility 3** – Memory forensics framework
- **SQLite** – Database for investigation management and analysis history

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
- Support for six Volatility 3 plugins
- Plugin selection through REST API
- JSON analysis results through FastAPI
- Analysis execution history stored in SQLite
- Analysis status tracking (`running`, `completed`, `failed`)
- Analysis timeout and error handling
- Plugin allowlisting to restrict supported analysis operations

### Windows System & Process Analysis

- `windows.info` – Extract Windows kernel and operating system information
- `windows.pslist` – Enumerate Windows processes
- `windows.pstree` – Analyze parent-child process relationships
- `windows.cmdline` – Extract process command-line arguments
- Retrieve process information including PID, PPID, process names, and creation times

### Memory & Network Analysis

- `windows.malfind` – Identify process memory regions with potentially suspicious characteristics
- `windows.netscan` – Extract network connection and socket information from Windows memory images
- Retrieve memory region information, including process identifiers, memory protections, and address ranges
- Retrieve network artifacts, including IP addresses, ports, protocols, connection states, and associated processes

## Planned Features

### Forensic Evidence Management

- Store detailed Volatility 3 analysis results
- Associate extracted evidence with analysis runs
- Retrieve and search forensic evidence
- Support evidence traceability across investigation cases

### Rule-Based Anomaly Detection

- Detect suspicious parent-child process relationships
- Identify suspicious process command-line patterns
- Analyze potentially malicious memory regions
- Identify suspicious network connection indicators
- Generate investigation findings and severity levels
- Associate detection findings with supporting evidence

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
│       └── volatility_runner.py
├── samples/              # Local memory images (not tracked)
├── data/                 # Local SQLite database
├── requirements.txt
├── .gitignore
└── README.md
```

Memory images, local databases, and Python virtual environments are excluded from Git version control.

The `samples` and `data` directories are used locally and may not appear in the cloned repository.

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
| POST | `/images/{image_id}/analyze` | Analyze a memory image using a selected Volatility 3 plugin |

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

Example response structure:

```json
{
  "run_id": 1,
  "image_id": 1,
  "plugin": "windows.pslist",
  "status": "completed",
  "results": []
}
```

The example above illustrates the response structure. Actual analysis results depend on the selected memory image and plugin.

## Current Limitations

- Memory image registration currently uses local file paths inside the `samples` directory.
- File extension validation does not guarantee that a file contains a valid Windows memory image.
- The backend currently supports six Volatility 3 plugins.
- Analysis results are returned as JSON, while execution metadata and history are stored in SQLite.
- Detailed forensic evidence storage has not yet been implemented.
- Automated anomaly detection rules have not yet been implemented.
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

Future development will focus on forensic evidence storage, rule-based anomaly detection, an interactive web dashboard, and forensic reporting.

## Disclaimer

This project is intended for educational and digital forensic research purposes.

Memory analysis results and suspicious indicators require further verification by a forensic analyst.

The presence of suspicious memory regions or network artifacts does not necessarily indicate malware or malicious activity.

Only analyze memory images obtained and used with appropriate authorization.
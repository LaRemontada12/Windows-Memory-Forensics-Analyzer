# Windows Memory Forensics Analyzer

A web-based Windows memory forensics and anomaly detection application powered by Volatility 3, Python, and FastAPI.

## Overview

This project aims to develop a tool for analyzing Windows memory images, identifying suspicious activities, and supporting digital forensic investigations.

The application integrates Volatility 3 with a FastAPI backend to automate memory analysis, manage investigation cases, analyze Windows processes, and maintain analysis execution history.

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

### Memory Image Management
- Memory image registration and validation
- Support for `.raw`, `.mem`, and `.vmem` file extensions
- SHA-256 hash calculation
- Memory image metadata storage and retrieval
- Association of memory images with investigation cases
- Basic API error handling

### Volatility 3 Integration
- Automated memory analysis using Volatility 3
- Support for multiple Volatility 3 plugins
- Plugin selection through REST API
- JSON analysis results through FastAPI
- Analysis execution history stored in SQLite
- Analysis status tracking (`running`, `completed`, `failed`)
- Analysis timeout and error handling

### Windows Memory & Process Analysis
- `windows.info` – Extract Windows kernel and operating system information
- `windows.pslist` – Enumerate Windows processes
- `windows.pstree` – Analyze parent-child process relationships
- `windows.cmdline` – Extract process command-line arguments
- Retrieve process information including PID, PPID, process names, and creation times

## Planned Features

### Advanced Memory Analysis
- Integration of additional Volatility 3 plugins:
  - `windows.malfind`
  - `windows.netscan`
- Memory injection indicators
- Network connection analysis
- Forensic evidence storage

### Anomaly Detection
- Suspicious process detection
- Suspicious command-line detection
- Abnormal parent-child process relationship detection
- Rule-based anomaly detection
- Investigation findings and severity classification

### Web Interface & Reporting
- Web dashboard
- Process tree visualization
- Analysis history visualization
- Forensic report generation
- Evaluation using Windows memory images

## Project Structure

```text
MemoryLab/
├── project/
│   └── backend/
│       ├── main.py
│       ├── database.py
│       └── volatility_runner.py
├── samples/              # Local memory images
├── data/                 # SQLite database
├── requirements.txt
├── .gitignore
└── README.md
```

Memory images, local databases, and Python virtual environments are excluded from Git version control.

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/LaRemontada12/Windows-Memory-Forensics-Analyzer.git
cd Windows-Memory-Forensics-Analyzer
```

**2. Create a Python virtual environment**

```powershell
python -m venv .venv
```

**3. Install dependencies**

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run Backend

Start the FastAPI server:

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --app-dir project/backend --reload
```

Open the API documentation:

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

The analysis API currently supports:

- `windows.info`
- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`

The plugin can be selected using the optional `plugin` query parameter. By default, the API executes `windows.info`.

## Current Limitations

- Memory image registration currently uses local file paths inside the `samples` directory.
- Automated analysis currently supports four Volatility 3 plugins.
- Analysis results are returned as JSON, while execution metadata and history are stored in SQLite.
- Automated anomaly detection rules have not yet been implemented.
- A dedicated web dashboard and forensic reporting system are not yet available.
- The current Volatility runner uses a Windows-specific executable path.

## Project Status

**Under active development.**

The following components have been implemented and tested:

- FastAPI backend and SQLite database
- Investigation case management
- Memory image registration and validation
- SHA-256 integrity hashing
- Automated Volatility 3 analysis
- Windows process enumeration and process tree analysis
- Process command-line extraction
- Analysis execution history and status tracking

Future development will focus on advanced memory analysis, anomaly detection, forensic evidence management, and a web-based investigation dashboard.

## Disclaimer

This project is intended for educational and digital forensic research purposes.

Memory analysis results and suspicious indicators require further verification by a forensic analyst.
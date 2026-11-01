# Windows Memory Forensics Analyzer

A web-based Windows memory forensics and anomaly detection application powered by Volatility 3, Python, and FastAPI.

## Overview

This project aims to develop a tool for analyzing Windows memory images, identifying suspicious activities, and supporting digital forensic investigations.

The application integrates Volatility 3 with a FastAPI backend to automate memory analysis, manage investigation cases, and maintain analysis execution history.

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
- Integration of the `windows.info` plugin
- JSON analysis results through REST API
- Analysis execution history stored in SQLite
- Analysis status tracking (`running`, `completed`, `failed`)
- Analysis timeout and error handling

## Planned Features

- Additional Volatility 3 plugins:
  - `windows.pslist`
  - `windows.pstree`
  - `windows.cmdline`
  - `windows.malfind`
  - `windows.netscan`
- Suspicious process and command-line detection
- Process tree visualization
- Memory injection indicators
- Suspicious network connection analysis
- Rule-based anomaly detection
- Forensic evidence storage
- Web dashboard
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
| POST | `/images/{image_id}/analyze` | Analyze a memory image using Volatility 3 |

## Current Limitations

- Memory image registration currently uses local file paths inside the `samples` directory.
- Automated analysis currently supports only `windows.info`.
- Analysis results are returned as JSON, while execution history is stored in SQLite.
- A dedicated web dashboard and automated anomaly detection rules have not yet been implemented.

## Project Status

**Under active development.**

The backend, investigation case management, memory image registration, and initial Volatility 3 integration have been implemented and tested.

## Disclaimer

This project is intended for educational and digital forensic research purposes.

Analysis results and detection indicators require verification by a forensic analyst.
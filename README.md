
# Windows Memory Forensics Analyzer

A Windows memory forensics and anomaly detection application powered by Volatility 3.

## Overview

This project aims to develop a web-based tool for analyzing Windows memory images, identifying suspicious activities, and supporting digital forensic investigations.

## Tech Stack

- Python
- FastAPI
- Volatility 3
- SQLite

## Implemented Features

- REST API backend using FastAPI
- SQLite database initialization
- Investigation case management
- Memory image registration
- Memory image validation
- SHA-256 hash calculation
- Memory image metadata storage and retrieval
- Basic API error handling

## Planned Features

- Automated Volatility 3 analysis
- Process tree visualization
- Suspicious command-line detection
- Memory injection indicators
- Network connection analysis
- Rule-based anomaly detection
- Web dashboard and forensic reporting

## Installation

```bash
pip install -r requirements.txt
```

## Run Backend

```bash
python -m uvicorn main:app --app-dir project/backend --reload
```

## API Documentation

After starting the backend, open:

http://127.0.0.1:8000/docs

## Project Status

Under active development.

## Disclaimer

This tool is intended for educational and digital forensic research purposes. Detection results require further analyst verification.

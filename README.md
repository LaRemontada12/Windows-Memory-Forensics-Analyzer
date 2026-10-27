# Windows Memory Forensics Analyzer

A Windows memory forensics and anomaly detection
application powered by Volatility 3.

## Tech Stack
- Python
- FastAPI
- Volatility 3
- SQLite

## Run

Install dependencies:

pip install -r requirements.txt

Start the backend:

python -m uvicorn main:app --app-dir project/backend --reload
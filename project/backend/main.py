from fastapi import FastAPI

app = FastAPI(
    title="Windows Memory Forensics",
    version="0.1.0"
)

@app.get("/")
def home():
    return {"message": "Memory Forensics API is running"}

@app.get("/health")
def health():
    return {"status": "ok"}
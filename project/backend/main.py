import sqlite3

from fastapi import FastAPI
from pydantic import BaseModel, Field
from database import DB_PATH, init_db

app = FastAPI(
    title="Windows Memory Forensics",
    version="0.1.0"
)

init_db()


# Dữ liệu đầu vào của phiên điều tra
class CaseCreate(BaseModel):
    title: str = Field(min_length=1)
    description: str | None = None


@app.get("/")
def home():
    return {"message": "Memory Forensics API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


# API tạo phiên điều tra
@app.post("/cases", status_code=201)
def create_case(case: CaseCreate):
    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.execute(
            """
            INSERT INTO cases (title, description)
            VALUES (?, ?)
            """,
            (case.title, case.description)
        )

        conn.commit()

        return {
            "id": cursor.lastrowid,
            "title": case.title,
            "description": case.description
        }
    finally:
        conn.close()


# API xem danh sách phiên điều tra
@app.get("/cases")
def get_cases():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY id DESC"
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()
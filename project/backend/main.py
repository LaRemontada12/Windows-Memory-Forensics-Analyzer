
import sqlite3
import hashlib
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from database import DB_PATH, init_db


# ==========================================
# 1. KHOI TAO UNG DUNG
# ==========================================

app = FastAPI(
    title="Windows Memory Forensics",
    version="0.1.0"
)

init_db()


# ==========================================
# 2. CAU HINH
# ==========================================

BASE_DIR = Path(__file__).resolve().parents[2]
SAMPLES_DIR = BASE_DIR / "samples"

ALLOWED_EXTENSIONS = {".raw", ".mem", ".vmem"}


# ==========================================
# 3. DATA MODELS
# ==========================================

class CaseCreate(BaseModel):
    title: str = Field(min_length=1)
    description: str | None = None


class MemoryImageCreate(BaseModel):
    file_path: str


# ==========================================
# 4. BASIC APIs - DAY 1
# ==========================================

@app.get("/")
def home():
    return {
        "message": "Memory Forensics API is running"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# ==========================================
# 5. CASE MANAGEMENT - DAY 2
# ==========================================

# Tao phien dieu tra
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


# Xem danh sach phien dieu tra
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


# ==========================================
# 6. MEMORY IMAGE MANAGEMENT - DAY 3
# ==========================================

# Dang ky anh RAM vao phien dieu tra
@app.post("/cases/{case_id}/images", status_code=201)
def register_image(case_id: int, image: MemoryImageCreate):

    file_path = Path(image.file_path).resolve()

    # Kiem tra file nam trong thu muc samples
    if not file_path.is_relative_to(SAMPLES_DIR.resolve()):
        raise HTTPException(
            status_code=400,
            detail="File must be inside samples directory"
        )

    # Kiem tra file ton tai
    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Memory image not found"
        )

    # Kiem tra dinh dang anh RAM
    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported memory image format"
        )

    conn = sqlite3.connect(DB_PATH)

    try:
        # Kiem tra phien dieu tra ton tai
        case = conn.execute(
            "SELECT id FROM cases WHERE id = ?",
            (case_id,)
        ).fetchone()

        if case is None:
            raise HTTPException(
                status_code=404,
                detail="Case not found"
            )

        # Tinh SHA-256 cho anh RAM
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4 * 1024 * 1024):
                    sha256.update(chunk)

            file_size = file_path.stat().st_size

        except OSError:
            raise HTTPException(
                status_code=400,
                detail="Cannot read memory image"
            )

        # Luu thong tin anh RAM vao SQLite
        cursor = conn.execute(
            """
            INSERT INTO memory_images
            (case_id, filename, file_path, sha256, size_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                case_id,
                file_path.name,
                str(file_path),
                sha256.hexdigest(),
                file_size
            )
        )

        conn.commit()

        return {
            "id": cursor.lastrowid,
            "case_id": case_id,
            "filename": file_path.name,
            "size_bytes": file_size,
            "sha256": sha256.hexdigest(),
            "status": "registered"
        }

    finally:
        conn.close()

# Xem danh sach Memory Images cua mot Case
@app.get("/cases/{case_id}/images")
def get_memory_images(case_id: int):

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        case = conn.execute(
            "SELECT id FROM cases WHERE id = ?",
            (case_id,)
        ).fetchone()

        if case is None:
            raise HTTPException(
                status_code=404,
                detail="Case not found"
            )

        rows = conn.execute(
            """
            SELECT * FROM memory_images
            WHERE case_id = ?
            ORDER BY id DESC
            """,
            (case_id,)
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()
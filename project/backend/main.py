import sqlite3
import hashlib
import subprocess
import json
from importlib.metadata import version
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from database import DB_PATH, init_db
from volatility_runner import run_volatility, ALLOWED_PLUGINS, VOL_PATH
from evidence_storage import save_evidence
from result_normalizer import (
    normalize_pslist_record,
    normalize_cmdline_record,
    normalize_malfind_record,
    normalize_netscan_record,
)


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
# 4. BASIC APIs
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
# 5. CASE MANAGEMENT
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
# 6. MEMORY IMAGE MANAGEMENT
# ==========================================

# Dang ky anh RAM vao phien dieu tra
@app.post("/cases/{case_id}/images", status_code=201)
def register_image(case_id: int, image: MemoryImageCreate):

    file_path = Path(image.file_path).resolve()

    # Kiem tra thu muc duoc phep
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

    # Kiem tra phan mo rong
    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported memory image format"
        )

    conn = sqlite3.connect(DB_PATH)

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

        # Tinh SHA-256 theo tung khoi 4 MB
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

        # Luu metadata vao SQLite
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


# ==========================================
# 7. ANALYSIS STATUS MANAGEMENT
# ==========================================

# Cap nhat lich su phan tich
def finish_analysis_run(run_id, status, error_message=None):

    conn = sqlite3.connect(DB_PATH)

    try:
        conn.execute(
            """
            UPDATE analysis_runs
            SET status = ?,
                finished_at = CURRENT_TIMESTAMP,
                error_message = ?
            WHERE id = ?
            """,
            (status, error_message, run_id)
        )

        conn.commit()

    finally:
        conn.close()


# ==========================================
# 8. VOLATILITY 3 ANALYSIS & EVIDENCE STORAGE
# ==========================================

@app.post("/images/{image_id}/analyze")
def analyze_image(
    image_id: int,
    plugin: Literal[
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.cmdline",
        "windows.malfind",
        "windows.netscan"
    ] = "windows.info"
):

    # ======================================
    # LAY THONG TIN ANH RAM
    # ======================================

    conn = sqlite3.connect(DB_PATH)

    try:
        image = conn.execute(
            """
            SELECT file_path
            FROM memory_images
            WHERE id = ?
            """,
            (image_id,)
        ).fetchone()

    finally:
        conn.close()

    if image is None:
        raise HTTPException(
            status_code=404,
            detail="Memory image not found in database"
        )

    image_path = Path(image[0]).resolve()

    # Kiem tra duong dan
    if not image_path.is_relative_to(SAMPLES_DIR.resolve()):
        raise HTTPException(
            status_code=400,
            detail="Memory image is outside samples directory"
        )

    # Kiem tra file ton tai
    if not image_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Memory image file not found"
        )

    # Kiem tra dinh dang
    if image_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported memory image format"
        )

    # ======================================
    # THU THAP VOLATILITY METADATA
    # ======================================

    # Lay phien ban Volatility 3 dang cai dat
    volatility_version = version("volatility3")

    # Ghi nhan tham so theo cau hinh volatility_runner.py
    plugin_params = {
        "executable": str(VOL_PATH),
        "arguments": [
            "-q",
            "-r", "json",
            "-f", str(image_path),
            ALLOWED_PLUGINS[plugin]
        ],
        "timeout_seconds": 300
    }

    # ======================================
    # TAO BAN GHI LICH SU PHAN TICH
    # ======================================

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.execute(
            """
            INSERT INTO analysis_runs
            (
                image_id,
                plugin_name,
                status,
                volatility_version,
                plugin_params_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                image_id,
                plugin,
                "running",
                volatility_version,
                json.dumps(
                    plugin_params,
                    ensure_ascii=False
                )
            )
        )

        run_id = cursor.lastrowid
        conn.commit()

    finally:
        conn.close()

    # ======================================
    # THUC THI VOLATILITY 3
    # ======================================

    try:
        result = run_volatility(
            image_path,
            plugin
        )

        # Luu tung ban ghi JSON vao SQLite
        evidence_count = save_evidence(
            run_id,
            result
        )

    except subprocess.TimeoutExpired:

        finish_analysis_run(
            run_id,
            "failed",
            "Analysis timed out"
        )

        raise HTTPException(
            status_code=504,
            detail="Volatility analysis timed out"
        )

    except Exception as exc:

        # Ghi lai loi neu phan tich hoac luu du lieu that bai
        finish_analysis_run(
            run_id,
            "failed",
            f"{type(exc).__name__}: {exc}"[:1000]
        )

        raise HTTPException(
            status_code=500,
            detail="Volatility analysis or evidence storage failed"
        ) from exc

    # ======================================
    # CAP NHAT PHAN TICH THANH CONG
    # ======================================

    finish_analysis_run(
        run_id,
        "completed"
    )

    # ======================================
    # TRA KET QUA CHO API
    # ======================================

    return {
        "run_id": run_id,
        "image_id": image_id,
        "plugin": plugin,
        "status": "completed",
        "volatility_version": volatility_version,
        "plugin_params": plugin_params,
        "evidence_count": evidence_count,
        "results": result
    }


# ==========================================
# 9. FORENSIC EVIDENCE RETRIEVAL
# ==========================================

@app.get("/analysis-runs/{run_id}/evidence")
def get_analysis_evidence(run_id: int):

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # Kiem tra lan phan tich co ton tai hay khong
        run = conn.execute(
            """
            SELECT
                id,
                image_id,
                plugin_name,
                status,
                volatility_version,
                plugin_params_json
            FROM analysis_runs
            WHERE id = ?
            """,
            (run_id,)
        ).fetchone()

        if run is None:
            raise HTTPException(
                status_code=404,
                detail="Analysis run not found"
            )

        # Lay cac ban ghi da luu, khong chay lai Volatility
        rows = conn.execute(
            """
            SELECT record_index, record_json
            FROM evidence
            WHERE run_id = ?
            ORDER BY record_index ASC
            """,
            (run_id,)
        ).fetchall()

        evidence = [
            {
                "record_index": row["record_index"],
                "data": json.loads(row["record_json"])
            }
            for row in rows
        ]

        # Bo sung du lieu chuan hoa theo plugin
        if run["plugin_name"] == "windows.pslist":
            for item in evidence:
                item["normalized"] = normalize_pslist_record(
                    item["data"]
                )

        elif run["plugin_name"] == "windows.cmdline":
            for item in evidence:
                item["normalized"] = normalize_cmdline_record(
                    item["data"]
                )

        elif run["plugin_name"] == "windows.malfind":
            for item in evidence:
                item["normalized"] = normalize_malfind_record(
                    item["data"]
                )

        elif run["plugin_name"] == "windows.netscan":
            for item in evidence:
                item["normalized"] = normalize_netscan_record(
                    item["data"]
                )

        return {
            "run_id": run_id,
            "image_id": run["image_id"],
            "plugin": run["plugin_name"],
            "status": run["status"],
            "volatility_version": run["volatility_version"],
            "plugin_params": (
                json.loads(run["plugin_params_json"])
                if run["plugin_params_json"] else None
            ),
            "evidence_count": len(evidence),
            "evidence": evidence
        }

    finally:
        conn.close()
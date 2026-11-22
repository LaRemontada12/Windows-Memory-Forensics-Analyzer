import sqlite3
from pathlib import Path

# ==========================================
# 1. DATABASE CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "data" / "forensics.db"


# ==========================================
# 2. DATABASE INITIALIZATION
# ==========================================

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            -- Investigation cases
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            -- Memory images
            CREATE TABLE IF NOT EXISTS memory_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            -- Analysis execution history
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_id INTEGER NOT NULL,
                plugin_name TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                finished_at TEXT,
                error_message TEXT,
                volatility_version TEXT,
                plugin_params_json TEXT,
                FOREIGN KEY (image_id) REFERENCES memory_images(id)
            );

            -- Forensic evidence
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                record_index INTEGER,
                record_json TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            -- Detection findings
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                evidence_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                FOREIGN KEY (evidence_id) REFERENCES evidence(id)
            );
        """)

        # ==========================================
        # 3. DATABASE MIGRATION
        # ==========================================

        # Lay danh sach cac cot cua bang analysis_runs
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(analysis_runs)"
            )
        }

        # Bo sung cot luu phien ban Volatility 3
        if "volatility_version" not in columns:
            conn.execute(
                """
                ALTER TABLE analysis_runs
                ADD COLUMN volatility_version TEXT
                """
            )

        # Bo sung cot luu tham so phan tich
        if "plugin_params_json" not in columns:
            conn.execute(
                """
                ALTER TABLE analysis_runs
                ADD COLUMN plugin_params_json TEXT
                """
            )


# ==========================================
# 4. RUN DATABASE INITIALIZATION
# ==========================================

if __name__ == "__main__":
    init_db()
    print(f"Database initialized: {DB_PATH}")
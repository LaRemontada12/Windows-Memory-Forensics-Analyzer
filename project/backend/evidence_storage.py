import json
import sqlite3

from database import DB_PATH


# Luu ket qua phan tich Volatility vao SQLite
def save_evidence(run_id: int, results: list) -> int:

    if not isinstance(results, list):
        raise ValueError("Analysis results must be a list")

    # Chuyen tung ban ghi thanh JSON
    records = []

    for index, record in enumerate(results):

        record_json = json.dumps(
            record,
            ensure_ascii=False
        )

        records.append((
            run_id,
            index,
            record_json
        ))

    # Luu du lieu vao bang evidence
    with sqlite3.connect(DB_PATH) as conn:

        conn.executemany(
            """
            INSERT INTO evidence
            (run_id, record_index, record_json)
            VALUES (?, ?, ?)
            """,
            records
        )

    return len(records)
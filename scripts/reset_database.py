#!/usr/bin/env python3
import json
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server import DB_PATH, EMPTY_STATE, MODULE_TABLES, UPLOAD_DIR, connect_db  # noqa: E402


def main():
    connect_db().close()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        for table in ("sessions", "documents", "audit_log", *MODULE_TABLES.values(), "users", "roles", "app_state"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    if UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO app_state (id, payload, updated_at)
            VALUES (1, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = CURRENT_TIMESTAMP
            """,
            (json.dumps(EMPTY_STATE, ensure_ascii=False),),
        )
        conn.commit()
    print(f"Database reset: {DB_PATH}")
    print("Akun awal: username admin / password admin12345")


if __name__ == "__main__":
    main()

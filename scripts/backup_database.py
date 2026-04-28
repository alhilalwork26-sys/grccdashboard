#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server import backup_database, connect_db  # noqa: E402


def main():
    connect_db().close()
    path = backup_database("manual")
    print(f"Backup dibuat: {path}")


if __name__ == "__main__":
    main()

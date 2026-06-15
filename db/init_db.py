#!/usr/bin/env python3
"""
Apply the ZYGANT PostgreSQL schema.

Usage (run from project root):
    python db/init_db.py

Requires DATABASE_URL to be set in .env or the environment.
Safe to run on an empty database only — will fail if types/tables already exist.
"""

import os
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv()

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def main():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")

    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(schema_sql)
        conn.commit()
        print("Schema applied successfully.")
    except psycopg2.errors.DuplicateObject as exc:
        conn.rollback()
        print(f"Schema already exists (already applied?): {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        conn.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()

import os
import re
import sys
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv


def split_sql_statements(sql_text):
    clean_lines = []
    for line in sql_text.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("--") or trimmed.startswith("/*"):
            continue
        clean_lines.append(line)
    
    clean_sql = "\n".join(clean_lines)
    statements = [stmt.strip() for stmt in clean_sql.split(";") if stmt.strip()]
    return statements


def main():
    base_dir = Path(__file__).resolve().parent
    load_dotenv(base_dir / ".env")

    missing = [
        name
        for name in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
        if not os.getenv(name)
    ]
    if missing:
        sys.exit("Missing required database configuration in .env: " + ", ".join(missing))

    try:
        db_port = int(os.getenv("DB_PORT", "3306"))
    except ValueError:
        sys.exit("DB_PORT must be an integer between 1 and 65535.")

    schema_path = base_dir / "schema.sql"
    if not schema_path.exists():
        sys.exit(f"Schema file not found at {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    host = os.getenv("DB_HOST", "127.0.0.1")
    user = os.environ["DB_USER"]
    password = os.environ["DB_PASSWORD"]
    database = os.environ["DB_NAME"]

    print(f"Connecting to MySQL database '{database}' on {host}:{db_port}...")

    try:
        conn = mysql.connector.connect(
            host=host,
            port=db_port,
            user=user,
            password=password,
            charset="utf8mb4",
            connection_timeout=15,
            use_pure=True,
        )
    except mysql.connector.Error as exc:
        sys.exit(f"Failed to connect to database: {exc}")

    try:
        cursor = conn.cursor()
        print("Executing schema.sql statements...")
        statements = split_sql_statements(schema_sql)
        for i, statement in enumerate(statements, 1):
            cursor.execute(statement)
        conn.commit()
        print(f"SUCCESS: Database schema applied successfully ({len(statements)} statements executed)!")
    except mysql.connector.Error as exc:
        conn.rollback()
        sys.exit(f"Database error executing schema: {exc}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()

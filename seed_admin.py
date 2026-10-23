import os
import re
import sys
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash


def main():
    load_dotenv(Path(__file__).resolve().with_name(".env"))
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")
    missing = [
        name
        for name in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
        if not os.getenv(name)
    ]
    if missing:
        sys.exit("Missing required database configuration: " + ", ".join(missing))
    try:
        db_port = int(os.getenv("DB_PORT", "3306"))
    except ValueError:
        sys.exit("DB_PORT must be an integer between 1 and 65535.")
    if not 1 <= db_port <= 65535:
        sys.exit("DB_PORT must be an integer between 1 and 65535.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", username):
        sys.exit("ADMIN_USERNAME must be 3–80 letters, digits, dots, dashes, or underscores.")
    if len(password) < 12 or len(password) > 128:
        sys.exit("ADMIN_PASSWORD must be between 12 and 128 characters.")

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=db_port,
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            database=os.environ["DB_NAME"],
            charset="utf8mb4",
            connection_timeout=5,
        )
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, is_active) "
            "VALUES (%s, %s, 'admin', 1)",
            (username, generate_password_hash(password)),
        )
        conn.commit()
    except mysql.connector.IntegrityError:
        if conn:
            conn.rollback()
        sys.exit("The administrator username already exists; no account was modified.")
    except mysql.connector.Error as exc:
        if conn:
            conn.rollback()
        sys.exit(f"Could not initialize the administrator account: {exc.__class__.__name__}. Check the database and schema.")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
    print("Initial administrator account created.")


if __name__ == "__main__":
    main()

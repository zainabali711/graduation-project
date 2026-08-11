"""One-time script: create admins table and insert the first admin account.

Usage (from project root, with venv active if you use one):
    python create_admin.py

Prompts securely for username and password — nothing is hardcoded.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=True)

# Ensure project root is importable
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from werkzeug.security import generate_password_hash

from app import app
from models import Admin, db


def main() -> int:
    print("=== CyberScan — Create Admin Account ===")
    print("This creates the `admins` table (if needed) and inserts one admin.\n")

    username = input("Admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return 1

    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if not password:
        print("Password cannot be empty.")
        return 1
    if password != confirm:
        print("Passwords do not match.")
        return 1
    if len(password) < 6:
        print("Password must be at least 6 characters.")
        return 1

    with app.app_context():
        db.create_all()
        existing = Admin.query.filter_by(username=username).first()
        if existing:
            print(f"Admin '{username}' already exists (id={existing.id}). Nothing changed.")
            return 0

        admin = Admin(
            username=username,
            password_hash=generate_password_hash(password, method="scrypt"),
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Created admin '{username}' (id={admin.id}).")
        print("Login at: /admin/login")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

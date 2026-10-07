"""Explicit local admin creation; no shipped/default privileged credentials."""
import getpass
import re
from pathlib import Path
from .storage import Store


def main():
    username = input("Admin username (3-40 letters, digits, _, ., -): ").strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
        raise SystemExit("Invalid username.")
    password = getpass.getpass("Password (8-128 characters): ")
    if not 8 <= len(password) <= 128 or password != getpass.getpass("Confirm password: "):
        raise SystemExit("Invalid password or confirmation mismatch.")
    store = Store(Path(__file__).parent / "phishguard.sqlite3")
    store.initialize()
    store.create_user(username, password, role="admin")
    print("Administrator created. Sign in using the UI.")


if __name__ == "__main__":
    main()

"""Create cloud tables. No local accounts, passwords or scan history are uploaded.

DATABASE_URL must refer to the dedicated PhishGuard database. This migration is
idempotent and only creates missing application tables and indexes.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dotenv import load_dotenv
from backend.postgres import PostgresStore

load_dotenv(".env.cloud")
dsn = os.environ.get("DATABASE_URL")
if not dsn:
    raise SystemExit("DATABASE_URL is required. No migration was run.")
PostgresStore(dsn).initialize()
print("Cloud schema is ready. No local user data was migrated.")

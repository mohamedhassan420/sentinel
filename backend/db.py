"""Database setup: one SQLite file, opened through SQLModel."""

import os
from pathlib import Path

from sqlalchemy import Engine
from sqlmodel import Session, SQLModel, create_engine

# Docker sets SENTINEL_DB so the file lives on a volume and survives restarts.
DB_PATH = os.environ.get("SENTINEL_DB", str(Path(__file__).parent / "sentinel.db"))

# check_same_thread=False: FastAPI handles requests on several threads, and
# each request gets its own Session, so sharing the engine is safe.
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})

# Add 1 whenever a table's columns change. SQLite keeps this number inside
# the database file (as "user_version"), so an old file can be recognised.
SCHEMA_VERSION = 3


def create_tables(db: Engine = engine) -> None:
    """Create the tables, first clearing out a database from an older version."""
    # ponytail: an out-of-date database is wiped, not migrated. That is fine
    # while every row is simulated and one click makes more. Switch to proper
    # migrations (Alembic) if Sentinel ever stores data worth keeping.
    with db.begin() as connection:
        if connection.exec_driver_sql("PRAGMA user_version").scalar() != SCHEMA_VERSION:
            SQLModel.metadata.drop_all(connection)
            connection.exec_driver_sql(f"PRAGMA user_version = {SCHEMA_VERSION}")
    SQLModel.metadata.create_all(db)


def get_session():
    """Give one request its own database session, closed when the request ends."""
    with Session(engine) as session:
        yield session

"""Database setup: one SQLite file, opened through SQLModel."""

import os
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# Docker sets SENTINEL_DB so the file lives on a volume and survives restarts.
DB_PATH = os.environ.get("SENTINEL_DB", str(Path(__file__).parent / "sentinel.db"))

# check_same_thread=False: FastAPI handles requests on several threads, and
# each request gets its own Session, so sharing the engine is safe.
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


def create_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    """Give one request its own database session, closed when the request ends."""
    with Session(engine) as session:
        yield session

"""Shared test setup: each test gets its own empty database."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from backend.db import get_session
from backend.main import app


@pytest.fixture(autouse=True)
def demo_mode(monkeypatch):
    """Every test starts in demo mode, so none can contact the real AI
    service (and spend money) by accident, whatever is set on this computer."""
    monkeypatch.setenv("SENTINEL_DEMO", "1")


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    def test_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = test_session
    yield TestClient(app)
    app.dependency_overrides.clear()
    engine.dispose()

"""Sentinel's web API. Run with: uvicorn backend.main:app"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, col, func, select

from backend import simulator
from backend.db import create_tables, get_session
from backend.models import Log, LogPage
from backend.simulator import noise


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()  # runs once when the server starts
    yield


app = FastAPI(title="Sentinel", lifespan=lifespan)

SessionDep = Annotated[Session, Depends(get_session)]
# Short text filters. The length limits stop anyone sending huge inputs.
TextFilter = Annotated[str | None, Query(max_length=100)]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/simulate/{scenario}")
def simulate(scenario: str, session: SessionDep) -> dict:
    """Write one attack scenario, mixed with background noise, into the log store."""
    if scenario not in simulator.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    logs = simulator.run(scenario)
    session.add_all(logs)
    session.commit()
    background = sum(log.scenario == noise.SCENARIO for log in logs)
    return {"added": len(logs), "attack": len(logs) - background, "background": background}


@app.get("/api/logs")
def list_logs(
    session: SessionDep,
    host: TextFilter = None,
    user: TextFilter = None,
    source: TextFilter = None,
    scenario: TextFilter = None,
    event_id: Annotated[int | None, Query(ge=0, le=65535)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> LogPage:
    """Newest logs first. Every filter is optional and they combine with AND."""
    filters = []
    # autoescape=True makes % and _ in the user's text match literally
    # instead of acting as SQL wildcards.
    if host:
        filters.append(col(Log.host).contains(host, autoescape=True))
    if user:
        filters.append(col(Log.user).contains(user, autoescape=True))
    if q:
        filters.append(col(Log.message).contains(q, autoescape=True))
    if source:
        filters.append(Log.source == source)
    if scenario:
        filters.append(Log.scenario == scenario)
    if event_id is not None:
        filters.append(Log.event_id == event_id)

    total = session.exec(select(func.count()).select_from(Log).where(*filters)).one()
    logs = session.exec(
        select(Log).where(*filters).order_by(col(Log.time).desc(), col(Log.id).desc()).limit(limit)
    ).all()
    return LogPage(total=total, logs=logs)


@app.get("/api/logs/filters")
def log_filter_options(session: SessionDep) -> dict:
    """The distinct values present in the log store, for the filter dropdowns."""
    def distinct(column):
        return session.exec(select(column).distinct().order_by(column)).all()

    return {
        "sources": distinct(Log.source),
        "event_ids": distinct(Log.event_id),
        "scenarios": distinct(Log.scenario),
    }


# In Docker the built React app sits next to the backend, and FastAPI serves
# it too. This must come last so the /api routes above are matched first.
FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

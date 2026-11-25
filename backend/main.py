"""Sentinel's web API. Run with: uvicorn backend.main:app"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, col, func, select

from backend import simulator
from backend.db import create_tables, get_session
from backend.engine import detection
from backend.models import Alert, AlertPage, Log, LogPage
from backend.simulator import noise

# The detection rules, read once when the server starts. A mistake in a rule
# file stops the server right here instead of hiding until an attack is missed.
RULES = detection.load_rules()


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
    """Write one attack scenario, mixed with background noise, into the log
    store, then run the detection rules over the new logs."""
    if scenario not in simulator.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    logs = simulator.run(scenario)
    session.add_all(logs)
    session.flush()  # gives every log its id, which the alerts point back to
    # ponytail: the rules see only this batch of new logs. Good enough while
    # every batch is a whole scenario. A real SIEM re-checks a sliding time
    # window, so a burst split across two batches is still counted.
    alerts = detection.detect(logs, RULES)
    session.add_all(alerts)
    background = sum(log.scenario == noise.SCENARIO for log in logs)
    result = {
        "added": len(logs),
        "attack": len(logs) - background,
        "background": background,
        "alerts": len(alerts),
    }
    session.commit()  # logs and alerts are saved together, or not at all
    return result


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
        # Firewall and email logs have no event ID, so skip the empty value.
        "event_ids": [event_id for event_id in distinct(Log.event_id) if event_id is not None],
        "scenarios": distinct(Log.scenario),
    }


@app.get("/api/alerts")
def list_alerts(session: SessionDep, limit: Annotated[int, Query(ge=1, le=1000)] = 200) -> AlertPage:
    """Newest alerts first."""
    total = session.exec(select(func.count()).select_from(Alert)).one()
    alerts = session.exec(
        select(Alert).order_by(col(Alert.time).desc(), col(Alert.id).desc()).limit(limit)
    ).all()
    return AlertPage(total=total, alerts=alerts)


# In Docker the built React app sits next to the backend, and FastAPI serves
# it too. This must come last so the /api routes above are matched first.
FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

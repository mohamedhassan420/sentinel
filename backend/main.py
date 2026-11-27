"""Sentinel's web API. Run with: uvicorn backend.main:app"""

import threading
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path as FilePath
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, Query
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, col, func, select

from backend import simulator
from backend.ai import triage
from backend.db import create_tables, get_session
from backend.engine import detection
from backend.explain import load_explanations
from backend.models import (
    FALSE_POSITIVE,
    OPEN_STATUSES,
    STATUSES,
    Alert,
    AlertDetail,
    AlertPage,
    Dashboard,
    Log,
    LogPage,
    ReviewChange,
    RuleDetail,
    RuleInfo,
    Severity,
    Status,
    StatusChange,
    TacticCount,
    Technique,
    TechniqueCount,
    Triage,
    TriageResult,
)
from backend.simulator import noise

# The detection rules, read once when the server starts. A mistake in a rule
# file stops the server right here instead of hiding until an attack is missed.
RULES = detection.load_rules()
RULES_BY_NAME = {rule.name: rule for rule in RULES}
# The Explain mode text for each rule, checked the same way.
EXPLANATIONS = load_explanations(set(RULES_BY_NAME))
# The stored AI answers that demo mode serves, one per rule. Checked too.
DEMO_ANSWERS = triage.load_demo_answers(set(RULES_BY_NAME))

# Only one triage is worked out at a time. Without this, two requests for
# the same alert arriving together would both ask the AI, and pay twice.
# ponytail: one lock for the whole app, so alerts opened at the same moment
# queue behind each other. Use one lock per alert if several analysts ever
# share a Sentinel.
TRIAGE_LOCK = threading.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()  # runs once when the server starts
    yield


app = FastAPI(title="Sentinel", lifespan=lifespan)

SessionDep = Annotated[Session, Depends(get_session)]
# Short text filters. The length limits stop anyone sending huge inputs.
TextFilter = Annotated[str | None, Query(max_length=100)]
# An alert's number in the address. The upper limit is the biggest number
# the database can hold, so a silly value is refused instead of crashing.
AlertId = Annotated[int, Path(ge=1, le=2**63 - 1)]


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
def list_alerts(
    session: SessionDep,
    status: Annotated[list[Status] | None, Query()] = None,
    severity: Severity | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> AlertPage:
    """Newest alerts first. `status` can be given more than once:
    ?status=New&status=In progress lists the alerts that are still open."""
    filters = []
    if status:
        filters.append(col(Alert.status).in_(status))
    if severity:
        filters.append(Alert.severity == severity)
    total = session.exec(select(func.count()).select_from(Alert).where(*filters)).one()
    alerts = session.exec(
        select(Alert).where(*filters).order_by(col(Alert.time).desc(), col(Alert.id).desc()).limit(limit)
    ).all()
    return AlertPage(total=total, alerts=alerts)


def _get_alert(session: Session, alert_id: int) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="No alert has that id")
    return alert


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: AlertId, session: SessionDep) -> AlertDetail:
    """One alert with its evidence: the logs that made the rule fire."""
    alert = _get_alert(session, alert_id)
    rule = RULES_BY_NAME.get(alert.rule_id)
    return AlertDetail(alert=alert, logs=_alert_logs(session, alert), rule=_rule_info(rule) if rule else None)


@app.patch("/api/alerts/{alert_id}")
def set_alert_status(alert_id: AlertId, change: StatusChange, session: SessionDep) -> Alert:
    """Move an alert through the queue. Only the status can be changed: what
    the rule saw is evidence, and evidence is never edited."""
    alert = _get_alert(session, alert_id)
    alert.status = change.status
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


def _alert_logs(session: Session, alert: Alert) -> list[Log]:
    """The alert's evidence, oldest first."""
    return session.exec(
        select(Log).where(col(Log.id).in_(alert.log_ids)).order_by(col(Log.time), col(Log.id))
    ).all()


def _get_triage(session: Session, alert_id: int) -> Triage | None:
    return session.exec(select(Triage).where(Triage.alert_id == alert_id)).first()


@app.post("/api/alerts/{alert_id}/triage")
def triage_alert(alert_id: AlertId, session: SessionDep) -> TriageResult:
    """The AI's triage of one alert. The first request works it out and
    stores it; every later request returns the stored one.

    If the AI cannot answer, nothing is stored and the reason is returned,
    so the page can show the rule's own explanation and offer to try again.
    """
    alert = _get_alert(session, alert_id)
    with TRIAGE_LOCK:
        stored = _get_triage(session, alert_id)
        if stored is None:
            try:
                stored = triage.suggest(
                    alert, RULES_BY_NAME.get(alert.rule_id), _alert_logs(session, alert), DEMO_ANSWERS
                )
            except triage.Unavailable as problem:
                return TriageResult(triage=None, problem=str(problem))
            session.add(stored)
            session.commit()
            session.refresh(stored)
    return TriageResult(triage=stored)


@app.patch("/api/alerts/{alert_id}/triage")
def review_triage(alert_id: AlertId, change: ReviewChange, session: SessionDep) -> Triage:
    """Record the analyst's decision. The AI's own words are left as they
    were; the analyst's go in the `final_` fields beside them."""
    stored = _get_triage(session, alert_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="This alert has no triage to review yet")
    agrees = (change.severity, change.summary, change.next_steps) == (
        stored.severity, stored.summary, stored.next_steps
    )
    stored.review = "Accepted" if agrees else "Edited"
    stored.final_severity = change.severity
    stored.final_summary = change.summary
    stored.final_next_steps = change.next_steps
    session.add(stored)
    session.commit()
    session.refresh(stored)
    return stored


@app.get("/api/dashboard")
def dashboard(session: SessionDep) -> Dashboard:
    """The counts on the home page."""
    open_by_severity = dict.fromkeys(detection.SEVERITIES.values(), 0)
    by_status = dict.fromkeys(STATUSES, 0)
    tactics, techniques = Counter(), Counter()
    # ponytail: this reads every alert and counts in Python, because the
    # tactics and techniques are stored as lists inside each row. Fine for a
    # few thousand alerts. Beyond that, give them their own table and let
    # the database count.
    rows = session.exec(select(Alert.severity, Alert.status, Alert.attack_tactics, Alert.attack_techniques)).all()
    for severity, status, alert_tactics, alert_techniques in rows:
        by_status[status] += 1
        if status in OPEN_STATUSES:
            open_by_severity[severity] += 1
        if status != FALSE_POSITIVE:
            tactics.update(alert_tactics)
            techniques.update(alert_techniques)
    return Dashboard(
        open_by_severity=open_by_severity,
        by_status=by_status,
        tactics=[TacticCount(tactic=tactic, alerts=tactics[tactic]) for tactic in detection.TACTICS.values()],
        techniques=[
            TechniqueCount(id=technique, name=detection.TECHNIQUES.get(technique, ""), alerts=count)
            for technique, count in sorted(techniques.items())
        ],
    )


def _rule_info(rule: detection.Rule) -> RuleInfo:
    return RuleInfo(
        name=rule.name,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        tactics=rule.tactics,
        techniques=[Technique(id=technique, name=detection.TECHNIQUES[technique]) for technique in rule.techniques],
        log_source=rule.source if rule.event_id is None else f"{rule.source} event {rule.event_id}",
        false_positives=rule.false_positives,
    )


@app.get("/api/rules")
def list_rules() -> list[RuleInfo]:
    """Every detection rule, in file name order."""
    return [_rule_info(rule) for rule in RULES]


@app.get("/api/rules/{name}")
def get_rule(name: Annotated[str, Path(max_length=100)]) -> RuleDetail:
    """One rule with its Explain mode text and the rule file itself."""
    # The name is only ever looked up among the rules loaded at startup. It
    # is never used to open a file, so it cannot be bent into reading others.
    rule = RULES_BY_NAME.get(name)
    if rule is None:
        raise HTTPException(status_code=404, detail="No rule has that name")
    return RuleDetail(
        **_rule_info(rule).model_dump(), yaml_text=rule.yaml_text, explanation=EXPLANATIONS[name]
    )


# In Docker the built React app sits next to the backend, and FastAPI serves
# it too. This must come last so the /api routes above are matched first.
FRONTEND_DIST = FilePath(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

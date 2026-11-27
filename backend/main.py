"""Sentinel's web API. Run with: uvicorn backend.main:app"""

import os
import threading
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path as FilePath
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, col, delete, func, select

from backend import simulator
from backend.ai import triage
from backend.db import create_tables, get_session
from backend.engine import correlation, detection
from backend.explain import load_explanations
from backend.models import (
    FALSE_POSITIVE,
    OPEN_STATUSES,
    STATUSES,
    Alert,
    AlertDetail,
    AlertPage,
    Dashboard,
    Incident,
    IncidentDetail,
    IncidentPage,
    IncidentStatus,
    IncidentSummary,
    Log,
    LogPage,
    ReviewChange,
    RuleDetail,
    RuleInfo,
    Severity,
    Status,
    StatusChange,
    SummaryResult,
    SummaryReview,
    TacticCount,
    Technique,
    TechniqueCount,
    TimelineStep,
    Triage,
    TriageResult,
)
from backend.reports import indicators, report
from backend.simulator import noise

# The detection rules, read once when the server starts. A mistake in a rule
# file stops the server right here instead of hiding until an attack is missed.
RULES = detection.load_rules()
RULES_BY_NAME = {rule.name: rule for rule in RULES}
# The Explain mode text for each rule, checked the same way.
EXPLANATIONS = load_explanations(set(RULES_BY_NAME))
# The stored AI answers that demo mode serves, one per rule. Checked too.
DEMO_ANSWERS = triage.load_demo_answers(set(RULES_BY_NAME))
# And the stored incident summaries, one per scenario.
DEMO_SUMMARIES = triage.load_demo_summaries(set(RULES_BY_NAME))

# Only one triage or incident summary is worked out at a time. Without this,
# two requests for the same alert arriving together would both ask the AI,
# and pay twice.
# ponytail: one lock for the whole app, so alerts opened at the same moment
# queue behind each other. Use one lock per alert if several analysts ever
# share a Sentinel.
TRIAGE_LOCK = threading.Lock()

# Laying out a PDF is the heaviest work Sentinel does, so only one report is
# made at a time. Without this, a burst of "Download report" requests would
# each claim memory at once and could bring a small server down. A request
# that arrives while a report is being made is told to try again at once.
# It does not wait in line: a waiting request would hold a worker thread
# and a database connection, and a few dozen of them would stall every page.
REPORT_LOCK = threading.Lock()

# The most log lines the store may hold. Anyone who can open the site can run
# scenarios, so without a limit the database would grow until the disk was
# full. See _make_room().
MAX_LOGS = 20_000


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()  # runs once when the server starts
    yield


# The biggest request body Sentinel accepts. Without a limit, one huge
# request is read whole into memory before anything checks it, and can crash
# the small public server. The largest real body, an edited incident summary,
# stays under this even in the worst case (9,000 characters, each written as
# a 6-byte JSON escape). Anything bigger is refused with "413 Content Too Large".
MAX_BODY_BYTES = 64 * 1024

app = FastAPI(title="Sentinel", lifespan=lifespan, max_body_size=MAX_BODY_BYTES)


# -------------------------------------------------------- Browser safeguards

# Sent with every answer. Each one switches on a protection that browsers
# have built in but leave off until a site asks for it.
SECURITY_HEADERS = {
    # Never guess a file's type from its contents: a file is what we say it is.
    "X-Content-Type-Options": "nosniff",
    # Do not tell other sites which Sentinel page a visitor came from.
    "Referrer-Policy": "no-referrer",
    # Once a browser has reached Sentinel over HTTPS, it keeps using HTTPS.
    # Browsers ignore this line on plain HTTP, so it does nothing on localhost.
    "Strict-Transport-Security": "max-age=31536000",
}
# The Content Security Policy: the page may load scripts, styles, fonts and
# images from Sentinel itself and from nowhere else, and may not run script
# written into the page. Log text is already shown as plain text, so this is
# a second lock on the same door: if attacker-written text ever did reach the
# page as HTML, the browser would still refuse to run it.
CONTENT_SECURITY_POLICY = "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"
# Which sites may show Sentinel inside a frame. A framed page can be used to
# trick a visitor into pressing its buttons (called clickjacking), so the
# answer is normally "none". Hugging Face shows every Space inside a frame on
# its own huggingface.co page, so the public demo's Dockerfile sets
# SENTINEL_FRAME_ANCESTORS=https://huggingface.co, and only that site may.
FRAME_ANCESTORS = os.environ.get("SENTINEL_FRAME_ANCESTORS", "'none'")
# FastAPI's own documentation pages load their script from a public library
# host, so the policy above would leave them blank. They show no log text.
PAGES_WITHOUT_POLICY = ("/docs", "/redoc")


@app.middleware("http")
async def browser_safeguards(request: Request, call_next):
    """Runs around every request: refuses writes that another website set
    off, and adds the security headers to every answer."""
    # A browser says where each request came from in the Sec-Fetch-Site
    # header. "same-origin" is Sentinel's own page. Anything else on a
    # request that changes data means some other website made the visitor's
    # browser send it (cross-site request forgery). On a private Sentinel in
    # live mode, that could spend the owner's AI credit behind their back.
    # Programs that are not browsers (curl, the tests) do not send the header.
    # ponytail: browsers from before 2023 do not send it either, and get no
    # protection here. Compare the Origin header with Host to cover them.
    came_from = request.headers.get("sec-fetch-site", "same-origin")
    if request.method not in ("GET", "HEAD", "OPTIONS") and came_from not in ("same-origin", "none"):
        return JSONResponse({"detail": "Requests from other websites are not accepted."}, status_code=403)
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if request.url.path.startswith(PAGES_WITHOUT_POLICY):
        # Without the policy, the older header is the only frame lock left.
        response.headers["X-Frame-Options"] = "DENY"
    else:
        response.headers["Content-Security-Policy"] = f"{CONTENT_SECURITY_POLICY}; frame-ancestors {FRAME_ANCESTORS}"
        if FRAME_ANCESTORS == "'none'":
            # The same rule for browsers too old to read frame-ancestors.
            # This header cannot name an allowed site, so it is left off
            # when one is allowed.
            response.headers["X-Frame-Options"] = "DENY"
    return response

SessionDep = Annotated[Session, Depends(get_session)]
# Short text filters. The length limits stop anyone sending huge inputs.
TextFilter = Annotated[str | None, Query(max_length=100)]
# An alert's number in the address. The upper limit is the biggest number
# the database can hold, so a silly value is refused instead of crashing.
AlertId = Annotated[int, Path(ge=1, le=2**63 - 1)]
IncidentId = AlertId  # an incident's number follows the same rules


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/simulate/{scenario}")
def simulate(scenario: str, session: SessionDep) -> dict:
    """Write one attack scenario, mixed with background noise, into the log
    store, run the detection rules over the new logs, and group the alerts
    they raise into incidents."""
    if scenario not in simulator.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    _make_room(session)
    logs = simulator.run(scenario)
    session.add_all(logs)
    session.flush()  # gives every log its id, which the alerts point back to
    # ponytail: the rules see only this batch of new logs. Good enough while
    # every batch is a whole scenario. A real SIEM re-checks a sliding time
    # window, so a burst split across two batches is still counted.
    alerts = detection.detect(logs, RULES)
    session.add_all(alerts)
    session.flush()  # gives every alert its id, before the alerts are grouped
    incidents = correlation.correlate(session, alerts)
    background = sum(log.scenario == noise.SCENARIO for log in logs)
    result = {
        "added": len(logs),
        "attack": len(logs) - background,
        "background": background,
        "alerts": len(alerts),
        "incidents": len(incidents),  # how many incidents those alerts went into
    }
    session.commit()  # logs, alerts and incidents are saved together, or not at all
    return result


def _make_room(session: Session) -> None:
    """Empty the store once it holds MAX_LOGS log lines, before a new
    scenario is written. Nothing is saved until the caller commits."""
    # ponytail: everything goes at once, because every row is simulated and
    # one click makes more. A store worth keeping would delete only its
    # oldest logs, and the alerts that point to them.
    if session.exec(select(func.count()).select_from(Log)).one() < MAX_LOGS:
        return
    # Rows that point to other rows go first.
    for table in (Triage, IncidentSummary, Alert, Incident, Log):
        session.exec(delete(table))


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
    open_incidents = set()  # an incident is open while any of its alerts is
    # ponytail: this reads every alert and counts in Python, because the
    # tactics and techniques are stored as lists inside each row. Fine for a
    # few thousand alerts. Beyond that, give them their own table and let
    # the database count.
    rows = session.exec(
        select(Alert.severity, Alert.status, Alert.attack_tactics, Alert.attack_techniques, Alert.incident_id)
    ).all()
    for severity, status, alert_tactics, alert_techniques, incident_id in rows:
        by_status[status] += 1
        if status in OPEN_STATUSES:
            open_by_severity[severity] += 1
            open_incidents.add(incident_id)
        if status != FALSE_POSITIVE:
            tactics.update(alert_tactics)
            techniques.update(alert_techniques)
    return Dashboard(
        open_by_severity=open_by_severity,
        by_status=by_status,
        open_incidents=len(open_incidents),
        tactics=[TacticCount(tactic=tactic, alerts=tactics[tactic]) for tactic in detection.TACTICS.values()],
        techniques=[
            TechniqueCount(id=technique, name=detection.TECHNIQUES.get(technique, ""), alerts=count)
            for technique, count in sorted(techniques.items())
        ],
    )


# ------------------------------------------------------------------ Incidents


@app.get("/api/incidents")
def list_incidents(
    session: SessionDep,
    status: IncidentStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> IncidentPage:
    """The incidents, the one with the newest alert first. `status` can be
    Open or Closed."""
    # ponytail: this reads every alert and groups them in Python, because an
    # incident's facts are worked out from its alerts and not stored. Fine
    # for a few thousand alerts. Beyond that, store each incident's times
    # and status on its own row and keep them up to date.
    grouped = defaultdict(list)
    for alert in session.exec(select(Alert).where(col(Alert.incident_id).is_not(None))).all():
        grouped[alert.incident_id].append(alert)
    incidents = [correlation.incident_info(number, alerts) for number, alerts in grouped.items()]
    if status:
        incidents = [incident for incident in incidents if incident.status == status]
    incidents.sort(key=lambda incident: (incident.end_time, incident.id), reverse=True)
    return IncidentPage(total=len(incidents), incidents=incidents[:limit])


def _incident_alerts(session: Session, incident_id: int) -> list[Alert]:
    """The incident's alerts, oldest first. An incident always has at least
    one, so none at all means there is no such incident."""
    alerts = session.exec(
        select(Alert).where(Alert.incident_id == incident_id).order_by(col(Alert.time), col(Alert.id))
    ).all()
    if not alerts:
        raise HTTPException(status_code=404, detail="No incident has that id")
    return alerts


def _evidence(session: Session, alerts: list[Alert]) -> dict[int, Log]:
    """Every log line the alerts point to, by log id."""
    log_ids = {log_id for alert in alerts for log_id in alert.log_ids}
    return {log.id: log for log in session.exec(select(Log).where(col(Log.id).in_(log_ids))).all()}


def _incident_detail(session: Session, incident_id: int) -> IncidentDetail:
    alerts = _incident_alerts(session, incident_id)
    logs = _evidence(session, alerts)
    real = correlation.real_alerts(alerts)  # leaves out false positives
    techniques = Counter(technique for alert in real for technique in alert.attack_techniques)
    return IncidentDetail(
        incident=correlation.incident_info(incident_id, alerts),
        # Each alert with the log line that set it off: its last one.
        timeline=[
            TimelineStep(alert=alert, evidence=logs.get(alert.log_ids[-1]) if alert.log_ids else None)
            for alert in alerts
        ],
        techniques=[
            TechniqueCount(id=technique, name=detection.TECHNIQUES.get(technique, ""), alerts=count)
            for technique, count in sorted(techniques.items())
        ],
        indicators=indicators.find(real, logs),
    )


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: IncidentId, session: SessionDep) -> IncidentDetail:
    """One incident: its alerts in time order, and what they add up to."""
    return _incident_detail(session, incident_id)


def _get_summary(session: Session, incident_id: int) -> IncidentSummary | None:
    return session.exec(select(IncidentSummary).where(IncidentSummary.incident_id == incident_id)).first()


@app.post("/api/incidents/{incident_id}/summary")
def summarise_incident(incident_id: IncidentId, session: SessionDep) -> SummaryResult:
    """The AI's summary of one incident. Like an alert's triage, the first
    request works it out and stores it, and later requests return the stored
    one. It is thrown away when new alerts join the incident."""
    alerts = _incident_alerts(session, incident_id)
    with TRIAGE_LOCK:
        stored = _get_summary(session, incident_id)
        if stored is None:
            try:
                stored = triage.summarise(
                    correlation.incident_info(incident_id, alerts), alerts, RULES_BY_NAME,
                    _evidence(session, alerts), DEMO_SUMMARIES,
                )
            except triage.Unavailable as problem:
                return SummaryResult(summary=None, problem=str(problem))
            # In live mode the AI takes several seconds. If a scenario run
            # added alerts to this incident meanwhile, the answer describes
            # an incident that has moved on, so it is not stored.
            now = session.exec(select(func.count()).select_from(Alert).where(Alert.incident_id == incident_id)).one()
            if now != len(alerts):
                return SummaryResult(
                    summary=None, problem="New alerts joined this incident while the AI was reading it."
                )
            session.add(stored)
            session.commit()
            session.refresh(stored)
    return SummaryResult(summary=stored)


@app.patch("/api/incidents/{incident_id}/summary")
def review_summary(incident_id: IncidentId, change: SummaryReview, session: SessionDep) -> IncidentSummary:
    """Record the analyst's decision about the summary. As with a triage,
    the AI's own words are kept and the analyst's go beside them."""
    stored = _get_summary(session, incident_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="This incident has no summary to review yet")
    agrees = (change.severity, change.summary, change.containment, change.recovery) == (
        stored.severity, stored.summary, stored.containment, stored.recovery
    )
    stored.review = "Accepted" if agrees else "Edited"
    stored.final_severity = change.severity
    stored.final_summary = change.summary
    stored.final_containment = change.containment
    stored.final_recovery = change.recovery
    session.add(stored)
    session.commit()
    session.refresh(stored)
    return stored


@app.get("/api/incidents/{incident_id}/report.pdf")
def incident_report(incident_id: IncidentId, session: SessionDep) -> Response:
    """The incident as a PDF report. It uses the stored summary if there is
    one (the analyst's version once reviewed), and plain facts if not."""
    # The lock is taken first, before the database is read, so a refused
    # request has used nothing but this one check.
    if not REPORT_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="Sentinel is busy making another report. Try again in a moment.")
    try:
        detail = _incident_detail(session, incident_id)
        html = report.render_html(detail, _get_summary(session, incident_id), datetime.now(timezone.utc))
        pdf = report.to_pdf(html)
    except report.Unavailable as problem:
        raise HTTPException(status_code=503, detail=str(problem))
    finally:
        REPORT_LOCK.release()
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinel-incident-{incident_id}.pdf"'},
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

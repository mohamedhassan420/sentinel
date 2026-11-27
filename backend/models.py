"""The database tables (logs, the alerts raised from them, the incidents the
alerts are grouped into, and the AI's suggestions) and the shapes of the
API's answers.

Real SOC tools receive logs from many sources (Windows, Sysmon, firewalls...)
and "normalise" them into one shape so the same rules can read them all.
This is Sentinel's shape: every simulated log line becomes one Log row.
"""

from datetime import datetime, timezone
from typing import Annotated, Literal, get_args

from pydantic import field_serializer
from sqlmodel import JSON, AutoString, Column, Field, SQLModel

from backend.explain import Explanation

Severity = Literal["Low", "Medium", "High", "Critical"]

# The life of an alert. An analyst picks it up ("In progress"), investigates,
# and closes it one of two ways: it was a real attack (true positive) or it
# was harmless activity the rule mistook for one (false positive).
Status = Literal["New", "In progress", "Closed as true positive", "Closed as false positive"]
STATUSES = get_args(Status)
OPEN_STATUSES = STATUSES[:2]  # still waiting for a decision
FALSE_POSITIVE = STATUSES[3]


def _as_utc(value: datetime) -> str:
    # SQLite forgets the time zone, so we state it again when sending to
    # the browser. Without this the browser would assume local time.
    return value.replace(tzinfo=timezone.utc).isoformat()


class Log(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    time: datetime = Field(index=True)  # always UTC
    host: str = Field(index=True)  # the machine the event happened on
    user: str = Field(index=True)  # the account the event is about
    source: str  # which tool wrote it, e.g. "Windows Security" or "Sysmon"
    # The tool's own code for the event type, e.g. 4625. Firewalls and mail
    # gateways do not number their events, so theirs is empty.
    event_id: int | None
    message: str  # the raw log text, for people to read and search
    # The same details as named fields, e.g. {"TargetUserName": "s.ahmed"}.
    # Detection rules test these, never the message text.
    fields: dict[str, str | int] = Field(sa_column=Column(JSON, nullable=False))
    scenario: str  # "background" for normal activity, or the attack's name

    _time_as_utc = field_serializer("time")(_as_utc)


class Incident(SQLModel, table=True):
    """A group of related alerts: one attack, seen as several detections.

    The row holds nothing but its number. Which alerts belong to it is
    recorded on the alerts (Alert.incident_id), and everything else about an
    incident (its hosts, users, times, severity and status) is worked out
    from those alerts each time it is asked for. Nothing is stored twice, so
    an incident can never disagree with its own alerts.
    """

    id: int | None = Field(default=None, primary_key=True)


class Alert(SQLModel, table=True):
    """One detection rule matching. A log records; an alert asks a person to look."""

    id: int | None = Field(default=None, primary_key=True)
    time: datetime = Field(index=True)  # when the last matching log happened (UTC)
    rule_id: str = Field(index=True)  # the rule's file name without ".yml"
    title: str  # the rule's title, copied so the alert reads on its own
    severity: str  # Low, Medium, High or Critical
    # MITRE ATT&CK: tactics are the attacker's goal ("Credential Access"),
    # techniques are the method ("T1110").
    attack_tactics: list[str] = Field(sa_column=Column(JSON, nullable=False))
    attack_techniques: list[str] = Field(sa_column=Column(JSON, nullable=False))
    host: str = Field(index=True)
    user: str = Field(index=True)
    log_ids: list[int] = Field(sa_column=Column(JSON, nullable=False))  # the evidence
    status: str = STATUSES[0]  # one of STATUSES; every alert starts as "New"
    # The incident this alert was grouped into: see engine/correlation.py.
    # Empty only for the instant between being raised and being grouped.
    incident_id: int | None = Field(default=None, foreign_key="incident.id", index=True)

    _time_as_utc = field_serializer("time")(_as_utc)


Confidence = Literal["Low", "Medium", "High"]
# One step of advice: a sentence, never empty and never a whole essay.
Step = Annotated[str, Field(min_length=1, max_length=500)]


class Suggestion(SQLModel):
    """A triage suggestion for one security alert."""

    # This class is exactly what the AI is allowed to answer, and the AI is
    # sent it as the format to follow. The answer is untrusted until it has
    # passed through here: anything missing, misspelt or over-long is
    # rejected, and the alert page falls back to the rule's own explanation.

    summary: str = Field(min_length=1, max_length=2000)  # what happened, in plain English
    # sa_type says how the database stores these two: as plain text.
    severity: Severity = Field(sa_type=AutoString)
    severity_reason: str = Field(min_length=1, max_length=1000)
    # What the analyst should do, most urgent first.
    next_steps: list[Step] = Field(min_length=1, max_length=8, sa_column=Column(JSON, nullable=False))
    confidence: Confidence = Field(sa_type=AutoString)  # how sure the AI is, given only this evidence


# Has a person looked at the suggestion yet, and did they agree with it?
Review = Literal["Not reviewed", "Accepted", "Edited"]


class Triage(Suggestion, table=True):
    """The AI's suggestion for one alert, and what the analyst decided.

    The fields inherited from Suggestion are the AI's words and are never
    changed, so there is always a record of what it said. The analyst's own
    decision is stored beside them in the `final_` fields.
    """

    id: int | None = Field(default=None, primary_key=True)
    alert_id: int = Field(foreign_key="alert.id", unique=True)  # one triage per alert
    source: str  # "live": Claude answered just now. "demo": a stored answer.
    model: str | None = None  # which Claude model answered (live mode only)

    review: str = "Not reviewed"  # one of Review
    # Empty until the analyst accepts or edits the suggestion.
    final_severity: str | None = None
    final_summary: str | None = None
    final_next_steps: list[str] | None = Field(default=None, sa_column=Column(JSON))


class TriageResult(SQLModel):
    """What POST /api/alerts/{id}/triage returns. When the AI cannot answer,
    `triage` is empty and `problem` says why in words safe to show anyone."""

    triage: Triage | None
    problem: str = ""


class ReviewChange(SQLModel):
    """What PATCH /api/alerts/{id}/triage accepts: the analyst's final word.
    Sending back exactly what the AI said counts as accepting it."""

    severity: Severity
    summary: str = Field(min_length=1, max_length=2000)
    next_steps: list[Step] = Field(max_length=8)


class IncidentSuggestion(SQLModel):
    """A summary of one security incident, for the incident report."""

    # Like Suggestion above, this class is exactly what the AI is allowed to
    # answer for an incident, and its answer is untrusted until it has
    # passed through here.

    summary: str = Field(min_length=1, max_length=3000)  # the story of the attack, for a manager
    severity: Severity = Field(sa_type=AutoString)  # of the incident as a whole
    severity_reason: str = Field(min_length=1, max_length=1000)
    # Containment: what stops the attack spreading, most urgent first.
    containment: list[Step] = Field(min_length=1, max_length=6, sa_column=Column(JSON, nullable=False))
    # Recovery: what removes the attacker's changes and returns to normal.
    recovery: list[Step] = Field(min_length=1, max_length=6, sa_column=Column(JSON, nullable=False))
    confidence: Confidence = Field(sa_type=AutoString)


class IncidentSummary(IncidentSuggestion, table=True):
    """The AI's summary of one incident, and what the analyst decided.

    It works like Triage: the AI's words are never changed, and the
    analyst's version is stored beside them in the `final_` fields.
    """

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="incident.id", unique=True)  # one summary per incident
    source: str  # "live" or "demo", as for Triage
    model: str | None = None

    review: str = "Not reviewed"  # one of Review
    final_severity: str | None = None
    final_summary: str | None = None
    final_containment: list[str] | None = Field(default=None, sa_column=Column(JSON))
    final_recovery: list[str] | None = Field(default=None, sa_column=Column(JSON))


class SummaryResult(SQLModel):
    """What POST /api/incidents/{id}/summary returns. When the AI cannot
    answer, `summary` is empty and `problem` says why."""

    summary: IncidentSummary | None
    problem: str = ""


class SummaryReview(SQLModel):
    """What PATCH /api/incidents/{id}/summary accepts: the analyst's final
    word. Sending back exactly what the AI said counts as accepting it."""

    severity: Severity
    summary: str = Field(min_length=1, max_length=3000)
    containment: list[Step] = Field(max_length=6)
    recovery: list[Step] = Field(max_length=6)


class LogPage(SQLModel):
    """What GET /api/logs returns: one page of logs plus the full match count."""

    total: int
    logs: list[Log]


class AlertPage(SQLModel):
    """What GET /api/alerts returns: one page of alerts plus the full count."""

    total: int
    alerts: list[Alert]


class StatusChange(SQLModel):
    """What PATCH /api/alerts/{id} accepts. Anything but the four statuses is rejected."""

    status: Status


class Technique(SQLModel):
    id: str  # e.g. "T1110"
    name: str  # e.g. "Brute Force"


class RuleInfo(SQLModel):
    """A detection rule as the app shows it."""

    name: str  # the file name without ".yml"; alerts store it as rule_id
    title: str
    description: str
    severity: Severity
    tactics: list[str]
    techniques: list[Technique]
    log_source: str  # which kind of log the rule reads, e.g. "Sysmon event 1"
    false_positives: list[str]


class RuleDetail(RuleInfo):
    """What GET /api/rules/{name} returns: everything on the Explain page."""

    yaml_text: str  # the rule file exactly as written
    explanation: Explanation


class AlertDetail(SQLModel):
    """What GET /api/alerts/{id} returns: the alert, the logs that made the
    rule fire, and the rule itself."""

    alert: Alert
    logs: list[Log]
    rule: RuleInfo | None  # None if the rule file has since been removed


class TacticCount(SQLModel):
    tactic: str
    alerts: int


class TechniqueCount(Technique):
    alerts: int


IncidentStatus = Literal["Open", "Closed"]


class IncidentInfo(SQLModel):
    """An incident as the app shows it. Every field is worked out from the
    incident's alerts: see incident_info() in engine/correlation.py."""

    id: int
    start_time: datetime  # the first alert
    end_time: datetime  # the latest alert
    severity: Severity  # the highest among its alerts
    status: IncidentStatus  # Open while any of its alerts still needs a decision
    hosts: list[str]  # the machines involved
    users: list[str]  # the accounts involved
    tactics: list[str]  # ATT&CK tactics, in the order they first appeared
    alerts: int  # how many alerts it holds
    open_alerts: int  # how many of them are New or In progress

    _times_as_utc = field_serializer("start_time", "end_time")(_as_utc)


class IncidentPage(SQLModel):
    """What GET /api/incidents returns: one page of incidents plus the full count."""

    total: int
    incidents: list[IncidentInfo]


class TimelineStep(SQLModel):
    """One step of an incident's timeline: an alert and the log line that
    set it off."""

    alert: Alert
    evidence: Log | None  # the last of the alert's log lines


class Indicator(SQLModel):
    """An indicator of compromise (IoC): a piece of evidence that can be
    searched for or blocked, such as an address the attacker used."""

    kind: str  # e.g. "IP address"
    value: str  # e.g. "198.51.100.23"
    alert_id: int  # the first alert whose evidence shows it
    alert_title: str


class IncidentDetail(SQLModel):
    """What GET /api/incidents/{id} returns: everything on the incident page."""

    incident: IncidentInfo
    timeline: list[TimelineStep]  # every alert, oldest first
    techniques: list[TechniqueCount]  # the ATT&CK techniques seen
    indicators: list[Indicator]


class Dashboard(SQLModel):
    """What GET /api/dashboard returns: the numbers on the home page."""

    open_by_severity: dict[Severity, int]  # alerts still waiting for a decision
    by_status: dict[Status, int]
    open_incidents: int  # incidents with at least one alert still waiting
    # How many alerts point to each tactic and technique. Alerts closed as
    # false positives are left out: nothing really happened there.
    tactics: list[TacticCount]  # all 14 tactics, in the order an attack moves
    techniques: list[TechniqueCount]  # only the techniques seen

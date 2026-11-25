"""The database tables (logs and the alerts raised from them) and the
shapes of the API's answers.

Real SOC tools receive logs from many sources (Windows, Sysmon, firewalls...)
and "normalise" them into one shape so the same rules can read them all.
This is Sentinel's shape: every simulated log line becomes one Log row.
"""

from datetime import datetime, timezone
from typing import Literal, get_args

from pydantic import field_serializer
from sqlmodel import JSON, Column, Field, SQLModel

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

    _time_as_utc = field_serializer("time")(_as_utc)


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


class Dashboard(SQLModel):
    """What GET /api/dashboard returns: the numbers on the home page."""

    open_by_severity: dict[Severity, int]  # alerts still waiting for a decision
    by_status: dict[Status, int]
    # How many alerts point to each tactic and technique. Alerts closed as
    # false positives are left out: nothing really happened there.
    tactics: list[TacticCount]  # all 14 tactics, in the order an attack moves
    techniques: list[TechniqueCount]  # only the techniques seen

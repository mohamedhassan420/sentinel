"""The database tables: logs and the alerts raised from them.

Real SOC tools receive logs from many sources (Windows, Sysmon, firewalls...)
and "normalise" them into one shape so the same rules can read them all.
This is Sentinel's shape: every simulated log line becomes one Log row.
"""

from datetime import datetime, timezone

from pydantic import field_serializer
from sqlmodel import JSON, Column, Field, SQLModel


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
    status: str = "New"  # Phase 3 adds the other statuses

    _time_as_utc = field_serializer("time")(_as_utc)


class LogPage(SQLModel):
    """What GET /api/logs returns: one page of logs plus the full match count."""

    total: int
    logs: list[Log]


class AlertPage(SQLModel):
    """What GET /api/alerts returns: one page of alerts plus the full count."""

    total: int
    alerts: list[Alert]

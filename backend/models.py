"""The common log format.

Real SOC tools receive logs from many sources (Windows, Sysmon, firewalls...)
and "normalise" them into one shape so the same rules can read them all.
This is Sentinel's shape: every simulated log line becomes one Log row.
"""

from datetime import datetime, timezone

from pydantic import field_serializer
from sqlmodel import Field, SQLModel


class Log(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    time: datetime = Field(index=True)  # always UTC
    host: str = Field(index=True)  # the machine that wrote the log
    user: str = Field(index=True)  # the account the event is about
    source: str  # which tool wrote it, e.g. "Windows Security" or "Sysmon"
    event_id: int  # the tool's own code for the event type, e.g. 4625
    message: str  # the raw log text
    scenario: str  # "background" for normal activity, or the attack's name

    @field_serializer("time")
    def _time_as_utc(self, value: datetime) -> str:
        # SQLite forgets the time zone, so we state it again when sending to
        # the browser. Without this the browser would assume local time.
        return value.replace(tzinfo=timezone.utc).isoformat()


class LogPage(SQLModel):
    """What GET /api/logs returns: one page of logs plus the full match count."""

    total: int
    logs: list[Log]

"""Correlation: grouping related alerts into incidents.

One attack rarely trips one rule. The full attack chain raises nine alerts,
and read one at a time they look like nine small problems. Correlation is
what notices they share a machine and a user and happened within half an
hour, and files them as one incident: one story for the analyst to follow.

Read this file top to bottom:

  1. When two alerts are linked
  2. Putting new alerts into incidents
  3. Describing an incident from its alerts
"""

from datetime import timedelta

from sqlalchemy import or_
from sqlmodel import Session, col, select

from backend.engine.detection import SEVERITIES
from backend.models import (
    FALSE_POSITIVE,
    OPEN_STATUSES,
    Alert,
    Incident,
    IncidentInfo,
    IncidentSummary,
)

# ---------------------------------------------------------- 1. Linked alerts

# How close in time two alerts must be to belong together.
WINDOW = timedelta(minutes=30)

# Machines that handle everybody's traffic. Two phishing emails to two
# different people are both logged by the mail gateway, but the gateway is
# all they have in common, so sharing one of these hosts links nothing. A
# real SOC keeps a longer list: web proxies, domain controllers, VPN servers.
SHARED_HOSTS = {"MAIL-GW-01"}


def linked(one: Alert, other: Alert) -> bool:
    """Do these two alerts belong to the same incident?

    Yes, if they happened within 30 minutes of each other AND they share a
    host or a user.
    """
    if abs(one.time - other.time) > WINDOW:
        return False
    same_host = one.host == other.host and one.host not in SHARED_HOSTS
    same_user = one.user == other.user
    return same_host or same_user


# ------------------------------------------- 2. New alerts into incidents

# An incident is a chain of linked alerts. A is linked to B and B to C, so
# all three are one incident, even if A and C are an hour apart or share
# nothing directly. That is how an attack that moves from the mailbox to the
# workstation, and keeps going for longer than 30 minutes, stays one story.


def correlate(session: Session, new_alerts: list[Alert]) -> set[int]:
    """Put each new alert into an incident. Returns the numbers of the
    incidents that gained an alert.

    The alerts must already be added to the session and flushed, so that
    each has its id.
    """
    for alert in sorted(new_alerts, key=lambda alert: alert.time):
        # The alerts already in an incident that this one is linked to. The
        # database narrows the search to the right host or user and the
        # right half hour. linked() then makes the real decision, so the
        # rule itself is written in one place only.
        nearby = session.exec(
            select(Alert).where(
                col(Alert.incident_id).is_not(None),
                or_(Alert.host == alert.host, Alert.user == alert.user),
                Alert.time >= alert.time - WINDOW,
                Alert.time <= alert.time + WINDOW,
            )
        ).all()
        found = sorted({other.incident_id for other in nearby if linked(alert, other)})

        if not found:  # linked to nothing: this alert starts a new incident
            incident = Incident()
            session.add(incident)
            session.flush()  # gives the new incident its number
            found = [incident.id]
        keep, *others = found
        if others:
            # This alert is linked to more than one incident, so they were
            # one attack all along. The oldest incident takes in the rest.
            _merge(session, keep, others)
        alert.incident_id = keep

    grown = {alert.incident_id for alert in new_alerts}
    # A summary written before these alerts arrived describes only part of
    # the incident now. It is removed, and a fresh one is written the next
    # time the incident is opened.
    _delete_summaries(session, grown)
    return grown


def _merge(session: Session, keep: int, others: list[int]) -> None:
    """Move every alert of the `others` incidents into `keep`, and remove
    the incidents left empty."""
    for alert in session.exec(select(Alert).where(col(Alert.incident_id).in_(others))).all():
        alert.incident_id = keep
    _delete_summaries(session, others)
    for number in others:
        session.delete(session.get(Incident, number))


def _delete_summaries(session: Session, incident_ids) -> None:
    stale = session.exec(select(IncidentSummary).where(col(IncidentSummary.incident_id).in_(incident_ids))).all()
    for summary in stale:
        session.delete(summary)


# ------------------------------------- 3. An incident, from its alerts

SEVERITY_ORDER = list(SEVERITIES.values())  # lowest first: Low ... Critical


def real_alerts(alerts: list[Alert]) -> list[Alert]:
    """The alerts that count towards what an incident says about itself.

    An alert closed as a false positive was harmless activity, so it stays
    on the timeline (marked as such) but adds nothing to the incident's
    severity, tactics, hosts or indicators. If every alert was a false
    positive, they all count again, so the incident can still say what it
    was about.
    """
    return [alert for alert in alerts if alert.status != FALSE_POSITIVE] or alerts


def _unique(values) -> list:
    """The values with repeats removed, in the order they first appear."""
    return list(dict.fromkeys(values))


def incident_info(incident_id: int, alerts: list[Alert]) -> IncidentInfo:
    """Work out everything the app shows about an incident from its alerts."""
    alerts = sorted(alerts, key=lambda alert: (alert.time, alert.id))
    real = real_alerts(alerts)
    open_alerts = sum(alert.status in OPEN_STATUSES for alert in alerts)
    return IncidentInfo(
        id=incident_id,
        start_time=alerts[0].time,
        end_time=alerts[-1].time,
        severity=max((alert.severity for alert in real), key=SEVERITY_ORDER.index),
        # Open until an analyst has decided about every one of its alerts.
        status="Open" if open_alerts else "Closed",
        # A shared host is where something was seen, not a machine the
        # attacker touched, so it is left off the list of hosts involved.
        hosts=_unique(alert.host for alert in real if alert.host not in SHARED_HOSTS),
        users=_unique(alert.user for alert in real),
        # In the order they first appeared: this is how the attack progressed.
        tactics=_unique(tactic for alert in real for tactic in alert.attack_tactics),
        alerts=len(alerts),
        open_alerts=open_alerts,
    )

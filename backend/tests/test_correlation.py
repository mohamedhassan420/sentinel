"""Tests for correlation: which alerts are linked, and how linked alerts
become incidents.

The alerts here are made by hand, so each test controls exactly who, where
and when. test_incidents.py runs the real scenarios through the API.
"""

import itertools
import random
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, SQLModel, create_engine, select

from backend.engine import correlation
from backend.models import Alert, Incident, IncidentSummary
from backend.simulator import events

T = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


def alert(minute: float, host: str, user: str) -> Alert:
    """An alert `minute` minutes after noon. Only its time, host and user matter here."""
    return Alert(
        time=T + timedelta(minutes=minute), rule_id="test_rule", title="Test alert", severity="Medium",
        attack_tactics=["Execution"], attack_techniques=["T1059.001"], host=host, user=user, log_ids=[],
    )


def raise_alerts(session: Session, *alerts: Alert) -> set[int]:
    """Store a batch of new alerts and correlate them, as the API does."""
    session.add_all(alerts)
    session.flush()
    grown = correlation.correlate(session, list(alerts))
    session.commit()
    return grown


def groups(session: Session) -> set[frozenset[int]]:
    """The incidents as stored: each one as the set of its alerts' ids."""
    by_incident: dict[int, set[int]] = {}
    for stored in session.exec(select(Alert)).all():
        assert stored.incident_id is not None  # every alert belongs to an incident
        by_incident.setdefault(stored.incident_id, set()).add(stored.id)
    # No incident is left behind without alerts.
    assert set(by_incident) == set(session.exec(select(Incident.id)).all())
    return {frozenset(ids) for ids in by_incident.values()}


def ids(*alerts: Alert) -> frozenset[int]:
    return frozenset(one.id for one in alerts)


# ------------------------------------------------------------ Linked alerts


def test_alerts_are_linked_by_a_shared_host_or_user():
    first = alert(0, "WKS-FIN-03", "a.khan")
    assert correlation.linked(first, alert(5, "WKS-FIN-03", "l.moreau"))  # same host
    assert correlation.linked(first, alert(5, "SRV-FILE-01", "a.khan"))  # same user
    assert correlation.linked(first, alert(5, "WKS-FIN-03", "a.khan"))  # both
    assert not correlation.linked(first, alert(5, "WKS-HR-02", "d.okafor"))  # neither


def test_alerts_more_than_30_minutes_apart_are_not_linked():
    first = alert(0, "WKS-FIN-03", "a.khan")
    assert correlation.linked(first, alert(30, "WKS-FIN-03", "a.khan"))  # exactly 30 minutes still counts
    assert not correlation.linked(first, alert(30.02, "WKS-FIN-03", "a.khan"))  # a second over
    # The order of the two makes no difference.
    assert correlation.linked(alert(30, "WKS-FIN-03", "a.khan"), first)
    assert not correlation.linked(alert(31, "WKS-FIN-03", "a.khan"), first)


def test_the_mail_gateway_links_nothing():
    # Everyone's email is logged by the same gateway. Two phishing emails to
    # two different people must not become one incident because of it.
    assert events.MAIL_GATEWAY_HOST in correlation.SHARED_HOSTS
    to_khan = alert(0, events.MAIL_GATEWAY_HOST, "a.khan")
    to_moreau = alert(1, events.MAIL_GATEWAY_HOST, "l.moreau")
    assert not correlation.linked(to_khan, to_moreau)
    # The user still links: the email to a.khan belongs with what happens
    # next on a.khan's workstation.
    assert correlation.linked(to_khan, alert(4, "WKS-FIN-03", "a.khan"))


# ------------------------------------------------------- Alerts into incidents


def test_linked_alerts_share_an_incident_and_others_get_their_own(session):
    one, two, elsewhere, later = (
        alert(0, "WKS-FIN-03", "a.khan"),
        alert(10, "WKS-FIN-03", "a.khan"),
        alert(10, "WKS-HR-02", "d.okafor"),  # another machine and another person
        alert(45, "WKS-FIN-03", "a.khan"),  # the same machine, but 35 minutes after `two`
    )
    grown = raise_alerts(session, one, two, elsewhere, later)
    assert groups(session) == {ids(one, two), ids(elsewhere), ids(later)}
    assert grown == {one.incident_id, elsewhere.incident_id, later.incident_id}


def test_a_chain_of_links_is_one_incident(session):
    # The first and last are 50 minutes apart and share neither host nor
    # user. The middle alert is linked to both, so all three are one attack.
    first = alert(0, "WKS-FIN-03", "a.khan")
    middle = alert(25, "WKS-FIN-03", "svc_update")
    last = alert(50, "SRV-FILE-01", "svc_update")
    assert not correlation.linked(first, last)
    raise_alerts(session, first, middle, last)
    assert groups(session) == {ids(first, middle, last)}


def test_a_later_batch_joins_the_incident_it_is_linked_to(session):
    first = alert(0, "WKS-FIN-03", "a.khan")
    raise_alerts(session, first)
    second, unrelated = alert(20, "WKS-FIN-03", "a.khan"), alert(20, "WKS-SALES-05", "m.rossi")
    grown = raise_alerts(session, second, unrelated)
    assert groups(session) == {ids(first, second), ids(unrelated)}
    assert second.incident_id == first.incident_id
    assert grown == {first.incident_id, unrelated.incident_id}


def test_an_alert_linked_to_two_incidents_makes_them_one(session):
    on_workstation = alert(0, "WKS-FIN-03", "a.khan")
    on_server = alert(5, "SRV-FILE-01", "svc_update")
    raise_alerts(session, on_workstation, on_server)
    assert groups(session) == {ids(on_workstation), ids(on_server)}
    older, newer = on_workstation.incident_id, on_server.incident_id
    # Both incidents have a summary, one already accepted by the analyst.
    for number in (older, newer):
        session.add(IncidentSummary(
            incident_id=number, summary="s", severity="High", severity_reason="r", containment=["c"],
            recovery=["r"], confidence="High", source="demo", review="Accepted",
        ))
    session.commit()

    # svc_update now appears on the workstation: the link between the two.
    bridge = alert(10, "WKS-FIN-03", "svc_update")
    grown = raise_alerts(session, bridge)

    assert groups(session) == {ids(on_workstation, on_server, bridge)}
    assert grown == {older}  # the older incident keeps its number
    assert session.get(Incident, newer) is None
    # Neither summary describes the merged incident, so both are gone.
    assert session.exec(select(IncidentSummary)).all() == []


def test_alerts_can_arrive_out_of_order(session):
    late = alert(50, "WKS-FIN-03", "a.khan")
    raise_alerts(session, late)
    early = alert(0, "WKS-FIN-03", "a.khan")
    raise_alerts(session, early)
    assert groups(session) == {ids(late), ids(early)}  # 50 minutes apart
    # An alert from in between arrives last and connects them.
    between = alert(25, "WKS-FIN-03", "a.khan")
    raise_alerts(session, between)
    assert groups(session) == {ids(late, early, between)}


def test_a_summary_is_dropped_when_its_incident_gains_an_alert(session):
    first, other = alert(0, "WKS-FIN-03", "a.khan"), alert(0, "WKS-HR-02", "d.okafor")
    raise_alerts(session, first, other)
    for number in (first.incident_id, other.incident_id):
        session.add(IncidentSummary(
            incident_id=number, summary="s", severity="High", severity_reason="r", containment=["c"],
            recovery=["r"], confidence="High", source="demo",
        ))
    session.commit()

    raise_alerts(session, alert(5, "WKS-FIN-03", "a.khan"))
    # Only the incident that grew lost its summary.
    assert [summary.incident_id for summary in session.exec(select(IncidentSummary)).all()] == [other.incident_id]


def slow_but_obvious_groups(alerts: list[Alert]) -> set[frozenset[int]]:
    """The right answer, worked out the simplest possible way: start with
    every alert alone, then join the groups of every linked pair."""
    found = [{one.id} for one in alerts]
    for one, other in itertools.combinations(alerts, 2):
        if correlation.linked(one, other):
            first = next(group for group in found if one.id in group)
            second = next(group for group in found if other.id in group)
            if first is not second:
                found.remove(second)
                first |= second
    return {frozenset(group) for group in found}


def test_incidents_are_exactly_the_chains_of_linked_alerts(tmp_path):
    # 40 random sets of alerts, arriving in random batches and in random
    # order. However they arrive, the stored incidents must be exactly the
    # groups the slow method finds.
    hosts = ["WKS-FIN-03", "WKS-HR-02", "SRV-FILE-01", events.MAIL_GATEWAY_HOST]
    users = ["a.khan", "d.okafor", "l.moreau", "svc_update"]
    for seed in range(40):
        rng = random.Random(seed)
        engine = create_engine(f"sqlite:///{tmp_path / f'{seed}.db'}")
        SQLModel.metadata.create_all(engine)
        alerts = [alert(rng.uniform(0, 300), rng.choice(hosts), rng.choice(users)) for _ in range(30)]
        with Session(engine) as session:
            waiting = list(alerts)
            while waiting:
                size = rng.randint(1, 8)
                raise_alerts(session, *waiting[:size])
                waiting = waiting[size:]
            assert groups(session) == slow_but_obvious_groups(alerts), f"seed {seed}"
        engine.dispose()


# ---------------------------------------------------- Describing an incident


def test_an_incident_is_described_from_its_alerts():
    email = alert(0, events.MAIL_GATEWAY_HOST, "a.khan")
    email.attack_tactics, email.severity = ["Initial Access"], "Medium"
    shell = alert(4, "WKS-FIN-03", "a.khan")
    shell.attack_tactics, shell.severity, shell.status = ["Execution", "Defense Evasion"], "High", "In progress"
    upload = alert(28, "WKS-FIN-03", "a.khan")
    upload.attack_tactics, upload.severity, upload.status = ["Exfiltration"], "Critical", "Closed as true positive"
    for number, one in enumerate((email, shell, upload), start=1):
        one.id = number

    info = correlation.incident_info(7, [upload, email, shell])  # given in any order
    assert (info.id, info.alerts, info.open_alerts, info.status) == (7, 3, 2, "Open")
    assert (info.start_time, info.end_time) == (email.time, upload.time)
    assert info.severity == "Critical"  # the highest of the three
    assert info.hosts == ["WKS-FIN-03"]  # the gateway saw the email; it was not attacked
    assert info.users == ["a.khan"]
    # Tactics in the order the attack reached them.
    assert info.tactics == ["Initial Access", "Execution", "Defense Evasion", "Exfiltration"]

    # Closed when no alert is waiting for a decision.
    email.status = shell.status = "Closed as true positive"
    assert correlation.incident_info(7, [email, shell, upload]).status == "Closed"

    # A false positive stops counting towards severity, tactics and hosts...
    upload.status = "Closed as false positive"
    info = correlation.incident_info(7, [email, shell, upload])
    assert info.severity == "High"
    assert info.tactics == ["Initial Access", "Execution", "Defense Evasion"]
    assert info.alerts == 3  # ...but it is still one of the incident's alerts.

    # If every alert was a false positive, they all count again.
    email.status = shell.status = "Closed as false positive"
    info = correlation.incident_info(7, [email, shell, upload])
    assert (info.severity, info.status, info.hosts) == ("Critical", "Closed", ["WKS-FIN-03"])

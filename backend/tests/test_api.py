from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session, create_engine, func, select

from backend.db import create_tables
from backend.models import Log
from backend.simulator import events


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_logs_and_alerts_start_empty(client):
    assert client.get("/api/logs").json() == {"total": 0, "logs": []}
    assert client.get("/api/alerts").json() == {"total": 0, "alerts": []}


def test_run_brute_force_adds_logs(client):
    result = client.post("/api/simulate/brute_force").json()
    assert result == {"added": 101, "attack": 41, "background": 60, "alerts": 2}

    page = client.get("/api/logs").json()
    assert page["total"] == 101
    # Newest first, and times carry a UTC offset so browsers read them correctly.
    times = [datetime.fromisoformat(log["time"]) for log in page["logs"]]
    assert times == sorted(times, reverse=True)
    assert times[0].utcoffset() == timedelta(0)


def test_brute_force_alerts_carry_their_evidence(client):
    client.post("/api/simulate/brute_force")
    page = client.get("/api/alerts").json()
    assert page["total"] == 2
    logon, failures = page["alerts"]  # newest first: the successful logon came last

    assert failures["rule_id"] == "win_security_many_failed_logons"
    assert failures["title"] == "Many Failed Logons For One Account"
    assert failures["severity"] == "Medium"
    assert failures["attack_tactics"] == ["Credential Access"]
    assert failures["attack_techniques"] == ["T1110"]
    assert (failures["host"], failures["user"]) == ("SRV-RDP-01", "s.ahmed")
    assert failures["status"] == "New"
    assert datetime.fromisoformat(failures["time"]).utcoffset() == timedelta(0)

    # The evidence is exactly the 40 failed logons of the attack.
    attack_failures = client.get("/api/logs", params={"scenario": "brute_force", "event_id": 4625}).json()["logs"]
    assert sorted(failures["log_ids"]) == sorted(log["id"] for log in attack_failures)

    assert logon["rule_id"] == "win_security_rdp_logon_from_public_ip"
    assert logon["severity"] == "High"
    (success,) = client.get("/api/logs", params={"scenario": "brute_force", "event_id": 4624}).json()["logs"]
    assert logon["log_ids"] == [success["id"]]


@pytest.mark.parametrize(
    "scenario, attack_lines, alerts",
    [
        ("phishing", 3, 2),
        ("powershell", 2, 2),
        ("privilege_escalation", 2, 2),
        ("exfiltration", 2, 2),
        ("full_chain", 9, 9),
    ],
)
def test_every_scenario_runs_and_raises_alerts(client, scenario, attack_lines, alerts):
    result = client.post(f"/api/simulate/{scenario}").json()
    assert result == {"added": 60 + attack_lines, "attack": attack_lines, "background": 60, "alerts": alerts}
    assert client.get("/api/logs", params={"scenario": scenario}).json()["total"] == attack_lines
    assert client.get("/api/alerts").json()["total"] == alerts

    # A second run adds to the alerts already there.
    client.post(f"/api/simulate/{scenario}")
    page = client.get("/api/alerts", params={"limit": 3}).json()
    assert page["total"] == alerts * 2
    assert len(page["alerts"]) == min(3, alerts * 2)


def test_logs_keep_their_fields(client):
    client.post("/api/simulate/exfiltration")
    (firewall,) = client.get("/api/logs", params={"scenario": "exfiltration", "source": "Firewall"}).json()["logs"]
    assert firewall["event_id"] is None  # firewalls do not number their events
    assert firewall["fields"]["dst_ip"] == events.ATTACKER_SERVER
    assert firewall["fields"]["bytes_sent"] >= 2_000_000_000


def test_filters_combine(client):
    client.post("/api/simulate/brute_force")

    failures = client.get("/api/logs", params={"scenario": "brute_force", "event_id": 4625}).json()
    assert failures["total"] == 40
    assert all(log["user"] == "s.ahmed" for log in failures["logs"])

    assert client.get("/api/logs", params={"host": "srv-rdp"}).json()["total"] == 41
    assert client.get("/api/logs", params={"q": "203.0.113.77"}).json()["total"] == 41
    assert client.get("/api/logs", params={"source": "Sysmon", "event_id": 4625}).json()["total"] == 0
    assert len(client.get("/api/logs", params={"limit": 5}).json()["logs"]) == 5


def test_filter_options_list_what_is_stored(client):
    client.post("/api/simulate/brute_force")
    client.post("/api/simulate/exfiltration")
    options = client.get("/api/logs/filters").json()
    # Background noise is random, so only what the two attacks guarantee is checked.
    assert {"Firewall", "Sysmon", "Windows Security"} <= set(options["sources"])
    assert {3, 4624, 4625} <= set(options["event_ids"])
    assert None not in options["event_ids"]  # firewall lines have no event ID
    assert options["event_ids"] == sorted(options["event_ids"])
    assert options["scenarios"] == ["background", "brute_force", "exfiltration"]


def test_search_text_is_not_a_sql_wildcard(client):
    client.post("/api/simulate/brute_force")
    # "%" matches everything in SQL LIKE. It must be treated as a plain character.
    assert client.get("/api/logs", params={"q": "%"}).json()["total"] == 0


def test_bad_input_is_rejected(client):
    assert client.post("/api/simulate/not_a_scenario").status_code == 404
    assert client.get("/api/logs", params={"limit": 0}).status_code == 422
    assert client.get("/api/logs", params={"event_id": "abc"}).status_code == 422
    assert client.get("/api/logs", params={"q": "x" * 201}).status_code == 422
    assert client.get("/api/alerts", params={"limit": 0}).status_code == 422
    assert client.get("/api/alerts", params={"limit": 1001}).status_code == 422


def test_a_database_from_an_older_version_is_rebuilt(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    # Phase 1's log table had no `fields` column.
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE log (id INTEGER PRIMARY KEY, message TEXT)")
        connection.exec_driver_sql("INSERT INTO log (message) VALUES ('from phase 1')")

    def count_logs() -> int:
        with Session(engine) as session:
            return session.exec(select(func.count()).select_from(Log)).one()

    create_tables(engine)
    assert count_logs() == 0  # the old rows are gone and the new table can be read

    with Session(engine) as session:
        session.add(events.logon_success(datetime(2026, 11, 25, 12, tzinfo=timezone.utc), "WKS-FIN-03", "a.khan", "10.0.20.13", 2, "test"))
        session.commit()
    create_tables(engine)  # a normal restart
    assert count_logs() == 1  # an up-to-date database is left alone
    engine.dispose()

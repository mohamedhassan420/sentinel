from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session, create_engine, func, select

from backend import main
from backend.db import create_tables
from backend.explain import load_explanations
from backend.models import Log
from backend.simulator import events


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_logs_and_alerts_start_empty(client):
    assert client.get("/api/logs").json() == {"total": 0, "logs": []}
    assert client.get("/api/alerts").json() == {"total": 0, "alerts": []}


def test_run_brute_force_adds_logs(client):
    result = client.post("/api/simulate/brute_force").json()
    assert result == {"added": 101, "attack": 41, "background": 60, "alerts": 2, "incidents": 1}

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
    assert result == {
        "added": 60 + attack_lines, "attack": attack_lines, "background": 60, "alerts": alerts, "incidents": 1,
    }
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


# ------------------------------------------------- Phase 3: queue and Explain


def test_alert_statuses_move_through_the_queue(client):
    client.post("/api/simulate/brute_force")
    logon, failures = client.get("/api/alerts").json()["alerts"]

    changed = client.patch(f"/api/alerts/{failures['id']}", json={"status": "In progress"})
    assert changed.status_code == 200
    assert changed.json()["status"] == "In progress"
    client.patch(f"/api/alerts/{logon['id']}", json={"status": "Closed as false positive"})

    def ids(**params):
        return [alert["id"] for alert in client.get("/api/alerts", params=params).json()["alerts"]]

    assert ids(status="In progress") == [failures["id"]]
    assert ids(status=["New", "In progress"]) == [failures["id"]]  # the open alerts
    assert ids(status="Closed as false positive") == [logon["id"]]
    assert ids(status="Closed as true positive") == []
    assert ids(severity="High") == [logon["id"]]
    assert ids(severity="High", status="New") == []  # filters combine with AND


def test_only_a_real_status_on_a_real_alert_is_accepted(client):
    client.post("/api/simulate/phishing")
    alert = client.get("/api/alerts").json()["alerts"][0]
    url = f"/api/alerts/{alert['id']}"

    assert client.patch(url, json={"status": "Deleted"}).status_code == 422
    assert client.patch(url, json={}).status_code == 422
    # Only the status can change. The evidence cannot be rewritten.
    client.patch(url, json={"status": "In progress", "severity": "Low", "log_ids": []})
    after = client.get(url).json()["alert"]
    assert after == {**alert, "status": "In progress"}

    assert client.patch("/api/alerts/999999", json={"status": "New"}).status_code == 404
    assert client.get("/api/alerts/999999").status_code == 404
    assert client.get("/api/alerts/0").status_code == 422
    assert client.get(f"/api/alerts/{10**30}").status_code == 422
    assert client.get("/api/alerts", params={"status": "Open"}).status_code == 422
    assert client.get("/api/alerts", params={"severity": "Severe"}).status_code == 422


def test_an_alert_opens_with_its_evidence_and_its_rule(client):
    client.post("/api/simulate/brute_force")
    logon, failures = client.get("/api/alerts").json()["alerts"]

    detail = client.get(f"/api/alerts/{failures['id']}").json()
    assert detail["alert"] == failures
    assert [log["id"] for log in detail["logs"]] == sorted(failures["log_ids"])  # 40 logs, oldest first
    assert {log["event_id"] for log in detail["logs"]} == {4625}
    assert detail["rule"]["name"] == "win_security_many_failed_logons"
    assert detail["rule"]["techniques"] == [{"id": "T1110", "name": "Brute Force"}]
    assert detail["rule"]["false_positives"]

    detail = client.get(f"/api/alerts/{logon['id']}").json()
    assert [log["event_id"] for log in detail["logs"]] == [4624]


def test_dashboard_counts(client):
    empty = client.get("/api/dashboard").json()
    assert empty["open_by_severity"] == {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    assert sum(empty["by_status"].values()) == 0
    assert len(empty["tactics"]) == 14  # every tactic is listed, seen or not
    assert empty["techniques"] == []

    client.post("/api/simulate/full_chain")  # 9 alerts
    board = client.get("/api/dashboard").json()
    assert board["open_by_severity"] == {"Low": 1, "Medium": 3, "High": 5, "Critical": 0}
    assert board["by_status"]["New"] == 9
    seen = {row["tactic"]: row["alerts"] for row in board["tactics"] if row["alerts"]}
    assert seen == {
        "Initial Access": 1, "Execution": 4, "Persistence": 2, "Privilege Escalation": 1,
        "Defense Evasion": 1, "Command and Control": 1, "Exfiltration": 2,
    }
    # The tactics come in the order an attack moves through them.
    assert [row["tactic"] for row in board["tactics"]][:3] == ["Reconnaissance", "Resource Development", "Initial Access"]
    assert {"id": "T1059.001", "name": "PowerShell", "alerts": 2} in board["techniques"]

    # Closing an alert takes it out of the open counts. Closing it as a
    # false positive also takes its technique off the map.
    alerts = client.get("/api/alerts").json()["alerts"]
    upload = next(alert for alert in alerts if alert["rule_id"] == "fw_large_upload_to_public_ip")
    ftp = next(alert for alert in alerts if alert["rule_id"] == "net_connection_win_ftp_to_public_ip")
    client.patch(f"/api/alerts/{upload['id']}", json={"status": "Closed as true positive"})
    client.patch(f"/api/alerts/{ftp['id']}", json={"status": "Closed as false positive"})
    board = client.get("/api/dashboard").json()
    assert board["open_by_severity"] == {"Low": 1, "Medium": 2, "High": 4, "Critical": 0}
    assert board["by_status"] == {
        "New": 7, "In progress": 0, "Closed as true positive": 1, "Closed as false positive": 1,
    }
    assert {row["tactic"]: row["alerts"] for row in board["tactics"]}["Exfiltration"] == 1
    assert "T1048.003" not in {row["id"] for row in board["techniques"]}


def test_every_rule_has_an_explain_page(client):
    rules = client.get("/api/rules").json()
    assert len(rules) == 10
    for rule in rules:
        page = client.get(f"/api/rules/{rule['name']}").json()
        assert page["title"] == rule["title"]
        assert page["yaml_text"].lstrip("# \n").startswith(("title:", "A threshold rule"))
        explanation = page["explanation"]
        for part in (explanation["attack"], explanation["log_shows"], explanation["why"],
                     explanation["security_plus"]["topic"], explanation["security_plus"]["text"]):
            assert part.strip()

    assert client.get("/api/rules/no_such_rule").status_code == 404
    assert client.get("/api/rules/..%2F..%2Fmain").status_code == 404
    assert client.get(f"/api/rules/{'x' * 101}").status_code == 422


def test_explanations_must_match_the_rules(tmp_path):
    good = "attack: a\nlog_shows: b\nwhy: c\nsecurity_plus: {topic: d, text: e}\n"
    (tmp_path / "rule_one.yml").write_text(good, encoding="utf-8")
    assert load_explanations({"rule_one"}, tmp_path)["rule_one"].security_plus.topic == "d"

    with pytest.raises(ValueError, match="rule_two"):  # a rule with no explanation
        load_explanations({"rule_one", "rule_two"}, tmp_path)
    with pytest.raises(ValueError, match="rule_one"):  # an explanation with no rule
        load_explanations(set(), tmp_path)

    (tmp_path / "rule_one.yml").write_text(good.replace("why:", "wy:"), encoding="utf-8")
    with pytest.raises(ValueError, match="rule_one.yml is not valid"):  # a misspelt heading
        load_explanations({"rule_one"}, tmp_path)


# ------------------------------------------------- Sentinel's own safeguards


def test_every_answer_carries_the_security_headers(client):
    headers = client.get("/api/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    # An error answer is protected too.
    assert client.get("/api/alerts/999").headers["X-Content-Type-Options"] == "nosniff"
    # FastAPI's documentation page loads its script from another host, so it
    # is the one place the content policy is left off.
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "Content-Security-Policy" not in docs.headers
    assert docs.headers["X-Frame-Options"] == "DENY"


def test_a_write_set_off_by_another_website_is_refused(client):
    for origin in ("cross-site", "same-site"):
        response = client.post("/api/simulate/brute_force", headers={"Sec-Fetch-Site": origin})
        assert response.status_code == 403
    assert client.get("/api/logs").json()["total"] == 0  # nothing was written

    # Sentinel's own page may write, and so may a program that is not a browser.
    assert client.post("/api/simulate/brute_force", headers={"Sec-Fetch-Site": "same-origin"}).status_code == 200
    assert client.post("/api/simulate/brute_force").status_code == 200
    # Changing a status and asking for a triage are writes as well.
    other_site = {"Sec-Fetch-Site": "cross-site"}
    assert client.patch("/api/alerts/1", json={"status": "In progress"}, headers=other_site).status_code == 403
    assert client.post("/api/alerts/1/triage", headers=other_site).status_code == 403
    # Reading is open to anyone: the browser itself keeps another website
    # from seeing the answer.
    assert client.get("/api/logs", headers=other_site).status_code == 200


def test_a_full_store_is_emptied_before_the_next_run(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_LOGS", 150)  # one brute force run writes 101 lines
    client.post("/api/simulate/brute_force")
    client.post("/api/alerts/1/triage")
    client.post("/api/incidents/1/summary")
    client.post("/api/simulate/brute_force")  # 101 is under the limit, so nothing is lost
    assert client.get("/api/logs").json()["total"] == 202
    assert client.get("/api/alerts").json()["total"] == 4

    client.post("/api/simulate/brute_force")  # 202 is over it: the store starts again
    assert client.get("/api/logs").json()["total"] == 101
    assert client.get("/api/alerts").json()["total"] == 2
    assert client.get("/api/incidents").json()["total"] == 1
    # The old alerts' AI suggestions went with them: the new alerts start unreviewed.
    for alert in client.get("/api/alerts").json()["alerts"]:
        assert client.post(f"/api/alerts/{alert['id']}/triage").json()["triage"]["review"] == "Not reviewed"


def test_a_huge_request_body_is_refused_before_it_is_read(client):
    # Scan finding F1: without a limit, this body would be read whole into
    # memory and parsed before anything checked it.
    client.post("/api/simulate/brute_force")
    huge = '{"status": "In progress", "padding": "' + "x" * 100_000 + '"}'
    response = client.patch("/api/alerts/1", content=huge, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    # A normal-sized request still works.
    assert client.patch("/api/alerts/1", json={"status": "In progress"}).status_code == 200

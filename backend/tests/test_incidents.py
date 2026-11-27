"""Tests for incidents through the API: the real scenarios, grouped and
shown as timelines."""

from datetime import datetime, timedelta

from backend.simulator import events

FULL_CHAIN_TACTICS = [
    "Initial Access", "Execution", "Defense Evasion", "Command and Control",
    "Persistence", "Privilege Escalation", "Exfiltration",
]


def incidents(client, **params) -> list[dict]:
    return client.get("/api/incidents", params=params).json()["incidents"]


def alert_of(client, rule_id: str) -> dict:
    """The first alert a rule raised."""
    alerts = client.get("/api/alerts").json()["alerts"]
    return next(alert for alert in alerts if alert["rule_id"] == rule_id)


def close(client, alert: dict, status: str = "Closed as true positive") -> None:
    assert client.patch(f"/api/alerts/{alert['id']}", json={"status": status}).status_code == 200


def test_the_full_attack_chain_is_one_incident(client):
    # Phase 5's "done when": one incident with four or more alerts.
    assert client.get("/api/incidents").json() == {"total": 0, "incidents": []}
    assert client.post("/api/simulate/full_chain").json()["incidents"] == 1

    page = client.get("/api/incidents").json()
    assert page["total"] == 1
    (incident,) = page["incidents"]
    assert incident["alerts"] == incident["open_alerts"] == 9
    assert (incident["hosts"], incident["users"]) == (["WKS-FIN-03"], ["a.khan"])
    assert (incident["severity"], incident["status"]) == ("High", "Open")
    assert incident["tactics"] == FULL_CHAIN_TACTICS  # the order the attack moved in

    # From the phishing email to the upload: 28 minutes, in UTC.
    start, end = (datetime.fromisoformat(incident[name]) for name in ("start_time", "end_time"))
    assert end - start == timedelta(minutes=28)
    assert start.utcoffset() == timedelta(0)

    # Every alert says which incident it belongs to.
    alerts = client.get("/api/alerts").json()["alerts"]
    assert {alert["incident_id"] for alert in alerts} == {incident["id"]}


def test_each_victim_gets_their_own_incident(client):
    for scenario in ("brute_force", "phishing", "powershell", "privilege_escalation", "exfiltration"):
        assert client.post(f"/api/simulate/{scenario}").json()["incidents"] == 1
    found = incidents(client)
    assert sorted(incident["users"] for incident in found) == [
        ["a.khan"], ["d.okafor"], ["l.moreau"], ["m.rossi"], ["s.ahmed"],
    ]
    assert all(incident["alerts"] == 2 for incident in found)

    # The full chain hits a.khan, whose exfiltration incident is minutes old:
    # its nine alerts join that incident. l.moreau's phishing incident stays
    # apart, although both phishing emails were logged by the mail gateway.
    assert client.post("/api/simulate/full_chain").json()["incidents"] == 1
    found = incidents(client)
    assert len(found) == 5
    by_user = {incident["users"][0]: incident for incident in found}
    assert by_user["a.khan"]["alerts"] == 11
    assert by_user["l.moreau"]["alerts"] == 2
    assert events.MAIL_GATEWAY_HOST not in by_user["a.khan"]["hosts"] + by_user["l.moreau"]["hosts"]
    # The incident with the newest alert comes first.
    assert found[0]["users"] == ["a.khan"]


def test_an_incident_is_open_until_every_alert_is_decided(client):
    client.post("/api/simulate/brute_force")
    client.post("/api/simulate/exfiltration")
    assert client.get("/api/dashboard").json()["open_incidents"] == 2
    alerts = client.get("/api/alerts").json()["alerts"]
    brute_force = [alert for alert in alerts if alert["user"] == "s.ahmed"]

    close(client, brute_force[0])
    (incident,) = [incident for incident in incidents(client) if incident["users"] == ["s.ahmed"]]
    assert (incident["status"], incident["open_alerts"], incident["alerts"]) == ("Open", 1, 2)

    close(client, brute_force[1])
    assert [incident["users"] for incident in incidents(client, status="Closed")] == [["s.ahmed"]]
    assert [incident["users"] for incident in incidents(client, status="Open")] == [["a.khan"]]
    assert client.get("/api/incidents").json()["total"] == 2
    assert client.get("/api/dashboard").json()["open_incidents"] == 1

    # Reopening an alert reopens its incident.
    client.patch(f"/api/alerts/{brute_force[0]['id']}", json={"status": "In progress"})
    assert len(incidents(client, status="Open")) == 2


def test_new_alerts_reopen_a_closed_incident(client):
    client.post("/api/simulate/exfiltration")
    for alert in client.get("/api/alerts").json()["alerts"]:
        close(client, alert)
    assert incidents(client)[0]["status"] == "Closed"

    client.post("/api/simulate/exfiltration")  # the same machine, minutes later
    (incident,) = incidents(client)
    assert (incident["status"], incident["alerts"], incident["open_alerts"]) == ("Open", 4, 2)


def test_the_timeline_tells_the_attack_in_order(client):
    client.post("/api/simulate/full_chain")
    detail = client.get("/api/incidents/1").json()
    assert detail["incident"] == incidents(client)[0]

    steps = detail["timeline"]
    assert [step["alert"]["rule_id"] for step in steps] == [
        "email_macro_attachment_external_sender",
        "proc_creation_win_office_spawns_shell",
        "proc_creation_win_office_spawns_shell",
        "proc_creation_win_powershell_encoded_command",
        "posh_ps_web_download",
        "win_security_local_account_created",
        "win_security_user_added_to_local_admins",
        "net_connection_win_ftp_to_public_ip",
        "fw_large_upload_to_public_ip",
    ]
    times = [step["alert"]["time"] for step in steps]
    assert times == sorted(times)
    for step in steps:
        # Each step carries the log line that set the alert off.
        assert step["evidence"]["id"] == step["alert"]["log_ids"][-1]
        assert step["evidence"]["time"] == step["alert"]["time"]
    assert steps[0]["evidence"]["source"] == "Email Gateway"
    assert "whoami" in steps[1]["evidence"]["message"]

    assert {"id": "T1059.001", "name": "PowerShell", "alerts": 2} in detail["techniques"]
    assert [technique["id"] for technique in detail["techniques"]] == sorted(
        technique["id"] for technique in detail["techniques"]
    )


def test_the_indicators_come_from_the_evidence(client):
    client.post("/api/simulate/full_chain")
    found = client.get("/api/incidents/1").json()["indicators"]
    attachment = next(indicator["value"] for indicator in found if indicator["kind"] == "File name")
    assert [(indicator["kind"], indicator["value"]) for indicator in found] == [
        ("IP address", events.ATTACKER_SERVER),
        ("Domain", "c0rp.example"),
        ("URL", f"http://{events.ATTACKER_SERVER}/update.ps1"),
        ("Email address", "accounts@c0rp.example"),
        ("File name", attachment),
        ("Account created", "svc_update"),
    ]
    assert attachment.startswith("Invoice_INV-") and attachment.endswith(".docm")
    # Each names the first alert that shows it: the download, not the later upload.
    address = found[0]
    assert address["alert_title"] == "PowerShell Script Downloads From The Web"
    assert client.get(f"/api/alerts/{address['alert_id']}").json()["alert"]["title"] == address["alert_title"]
    # The victim's own address (10.0.20.13) is in the evidence too, and is not an indicator.
    assert not any(indicator["value"].startswith("10.") for indicator in found)

    # 40 failed logons from one address are one indicator, not 40.
    client.post("/api/simulate/brute_force")
    found = client.get("/api/incidents/2").json()["indicators"]
    assert [(indicator["kind"], indicator["value"]) for indicator in found] == [("IP address", "203.0.113.77")]


def test_a_false_positive_stops_counting(client):
    client.post("/api/simulate/privilege_escalation")
    created = alert_of(client, "win_security_local_account_created")  # Low, Persistence
    added = alert_of(client, "win_security_user_added_to_local_admins")  # High, Persistence + Privilege Escalation
    before = client.get("/api/incidents/1").json()
    assert before["incident"]["severity"] == "High"
    assert before["incident"]["tactics"] == ["Persistence", "Privilege Escalation"]

    close(client, added, "Closed as false positive")
    after = client.get("/api/incidents/1").json()
    assert after["incident"]["severity"] == "Low"
    assert after["incident"]["tactics"] == ["Persistence"]
    assert [technique["id"] for technique in after["techniques"]] == ["T1136.001"]
    assert (after["incident"]["alerts"], after["incident"]["open_alerts"]) == (2, 1)
    # It stays on the timeline, marked with its status.
    assert [step["alert"]["status"] for step in after["timeline"]] == ["New", "Closed as false positive"]
    # The account it created is still an indicator: the other alert shows it.
    assert [indicator["value"] for indicator in after["indicators"]] == ["svc_update"]

    # With both closed as false positives the incident is closed, and it
    # says again what it was about.
    close(client, created, "Closed as false positive")
    closed = client.get("/api/incidents/1").json()["incident"]
    assert (closed["status"], closed["severity"]) == ("Closed", "High")


def test_bad_incident_requests_are_rejected(client):
    client.post("/api/simulate/phishing")
    assert client.get("/api/incidents/1").status_code == 200
    for path in ("/api/incidents/999999", "/api/incidents/999999/report.pdf"):
        assert client.get(path).status_code == 404
    assert client.post("/api/incidents/999999/summary").status_code == 404
    assert client.get("/api/incidents/0").status_code == 422
    assert client.get(f"/api/incidents/{10**30}").status_code == 422
    assert client.get("/api/incidents/abc").status_code == 422
    assert client.get("/api/incidents", params={"status": "New"}).status_code == 422
    assert client.get("/api/incidents", params={"limit": 0}).status_code == 422
    assert len(client.get("/api/incidents", params={"limit": 1}).json()["incidents"]) == 1

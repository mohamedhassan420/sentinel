"""Background noise: what a normal half hour in a small office looks like.

Real attacks are hidden inside thousands of harmless events. Without noise,
every log would be an attack log and a detection rule could never be wrong,
so we could not test for false positives (alerts on harmless activity).

Several lines here are deliberate near-misses: they look a little like an
attack, and a carelessly written rule would fire on them.
"""

import random
from datetime import datetime, timedelta

from backend.models import Log
from backend.simulator import events

SCENARIO = "background"

# The fake company's staff: (user, their workstation, its internal IP address).
STAFF = [
    ("a.khan", "WKS-FIN-03", "10.0.20.13"),
    ("l.moreau", "WKS-FIN-07", "10.0.20.17"),
    ("d.okafor", "WKS-HR-02", "10.0.30.12"),
    ("s.ahmed", "WKS-IT-01", "10.0.40.11"),
    ("m.rossi", "WKS-SALES-05", "10.0.50.15"),
    ("j.tanaka", "WKS-SALES-09", "10.0.50.19"),
]
IT_ADMIN = STAFF[3]

# Everyday programs, all started by the Windows desktop (explorer.exe).
NORMAL_PROGRAMS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    events.OUTLOOK,
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    events.WINWORD,
    r"C:\Users\Public\Teams\ms-teams.exe",
]

# Ordinary email: (sender, subject, attachment). The last one is a
# macro-enabled file, but from a colleague, which is routine in finance.
NORMAL_EMAILS = [
    ("newsletter@logistics-weekly.example", "This week in logistics", None),
    ("billing@supplier.example", "Statement for October", "Statement_October.pdf"),
    ("hr@corp.example", "Updated holiday calendar", "Holidays_2027.xlsx"),
    ("finance-team@corp.example", "Budget model for review", "Budget_FY27.xlsm"),
]

# Scripts the IT administrator runs. None of them downloads anything.
ADMIN_SCRIPTS = [
    "Get-Service | Where-Object Status -eq 'Stopped'",
    "Get-EventLog -LogName System -Newest 50",
    "Test-Connection -ComputerName SRV-FILE-01 -Count 2",
]


def generate(end: datetime, rng: random.Random, minutes: int = 30, count: int = 60) -> list[Log]:
    """Return `count` normal log lines spread over the `minutes` before `end`."""
    logs = []
    for _ in range(count):
        time = end - timedelta(seconds=rng.uniform(0, minutes * 60))
        user, host, ip = rng.choice(STAFF)
        kind = rng.choices(["logon", "program", "typo", "email", "web", "script"],
                           weights=[40, 22, 5, 13, 16, 4])[0]
        if kind == "logon":
            logs.append(events.logon_success(time, host, user, ip, events.LOGON_INTERACTIVE, SCENARIO))
        elif kind == "program":
            logs.append(events.process_create(time, host, user, rng.choice(NORMAL_PROGRAMS),
                                              events.EXPLORER, SCENARIO))
        elif kind == "typo":
            # Someone mistypes a password: a single 4625 is normal, a burst is not.
            logs.append(events.logon_failure(time, host, user, ip, events.LOGON_INTERACTIVE, SCENARIO))
        elif kind == "email":
            sender, subject, attachment = rng.choice(NORMAL_EMAILS)
            logs.append(events.email_delivered(time, user, sender, subject, attachment, SCENARIO))
        elif kind == "web":
            # Browsing: a little goes up, a lot comes down. 192.0.2.0/24 is
            # another range reserved for examples (RFC 5737).
            logs.append(events.firewall_session(
                time, host, user, ip, f"192.0.2.{rng.randint(1, 254)}", 443,
                bytes_sent=rng.randint(2_000, 40_000_000),
                bytes_received=rng.randint(50_000, 400_000_000), scenario=SCENARIO))
        else:
            user, host, ip = IT_ADMIN
            logs.append(events.script_block(time, host, user, rng.choice(ADMIN_SCRIPTS), SCENARIO))
    return sorted(logs, key=lambda log: log.time)

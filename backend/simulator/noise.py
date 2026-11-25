"""Background noise: what a normal half hour in a small office looks like.

Real attacks are hidden inside thousands of harmless events. Without noise,
every log would be an attack log and a detection rule could never be wrong,
so we could not test for false positives (alerts on harmless activity).
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

# Everyday programs, all started by the Windows desktop (explorer.exe).
NORMAL_PROGRAMS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Users\Public\Teams\ms-teams.exe",
]


def generate(end: datetime, rng: random.Random, minutes: int = 30, count: int = 60) -> list[Log]:
    """Return `count` normal log lines spread over the `minutes` before `end`."""
    logs = []
    for _ in range(count):
        time = end - timedelta(seconds=rng.uniform(0, minutes * 60))
        user, host, ip = rng.choice(STAFF)
        # Mostly successful logons and programs starting. Now and then someone
        # mistypes a password: a single 4625 is normal, a burst of them is not.
        kind = rng.choices(["logon", "program", "typo"], weights=[60, 35, 5])[0]
        if kind == "logon":
            logs.append(events.logon_success(time, host, user, ip, events.LOGON_INTERACTIVE, SCENARIO))
        elif kind == "program":
            logs.append(events.process_create(time, host, user, rng.choice(NORMAL_PROGRAMS),
                                              r"C:\Windows\explorer.exe", SCENARIO))
        else:
            logs.append(events.logon_failure(time, host, user, ip, events.LOGON_INTERACTIVE, SCENARIO))
    return sorted(logs, key=lambda log: log.time)

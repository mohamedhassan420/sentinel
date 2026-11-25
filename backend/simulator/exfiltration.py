"""Scenario: data exfiltration (MITRE ATT&CK T1048).

A workstation uploads about 2 GB to the attacker's server over FTP. Two log
sources see it: Sysmon records ftp.exe opening the connection, and the
firewall records how much data had been sent when the connection closed.
"""

import random
from datetime import datetime, timedelta

from backend.models import Log
from backend.simulator import events, noise

SCENARIO = "exfiltration"

VICTIM = noise.STAFF[0]  # a.khan in finance
FTP_EXE = r"C:\Windows\System32\ftp.exe"  # the FTP program built into Windows
FTP_PORT = 21


def generate(end: datetime, rng: random.Random, victim: tuple = VICTIM) -> list[Log]:
    """Return the attack's log lines, finishing at `end`."""
    user, host, ip = victim
    return [
        # The upload takes about twelve minutes, so the connection opens well
        # before the firewall can report its size.
        events.network_connection(end - timedelta(minutes=12), host, user, FTP_EXE,
                                  ip, events.ATTACKER_SERVER, FTP_PORT, SCENARIO),
        events.firewall_session(end, host, user, ip, events.ATTACKER_SERVER, FTP_PORT,
                                bytes_sent=rng.randint(2_000_000_000, 2_300_000_000),
                                bytes_received=rng.randint(20_000, 90_000), scenario=SCENARIO),
    ]

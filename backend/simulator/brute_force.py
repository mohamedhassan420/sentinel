"""Scenario: brute force login (MITRE ATT&CK T1110).

The attacker guesses passwords for one account over Remote Desktop:
40 failed logons (event 4625) in under 2 minutes, then one success (4624).
The success is the dangerous part: it means a guess worked.
"""

import random
from datetime import datetime, timedelta

from backend.models import Log
from backend.simulator import events

SCENARIO = "brute_force"

TARGET_HOST = "SRV-RDP-01"
TARGET_USER = "s.ahmed"
# 203.0.113.0/24 is reserved for documentation and examples (RFC 5737),
# so this address can never belong to a real machine.
ATTACKER_IP = "203.0.113.77"
FAILED_ATTEMPTS = 40


def generate(end: datetime, rng: random.Random) -> list[Log]:
    """Return the attack's log lines, finishing at `end`."""
    start = end - timedelta(minutes=2)
    # Failures land at random moments in the first 115 seconds...
    failure_times = sorted(start + timedelta(seconds=rng.uniform(0, 115)) for _ in range(FAILED_ATTEMPTS))
    logs = [
        events.logon_failure(time, TARGET_HOST, TARGET_USER, ATTACKER_IP, events.LOGON_REMOTE_DESKTOP, SCENARIO)
        for time in failure_times
    ]
    # ...and the correct guess comes last.
    logs.append(
        events.logon_success(end, TARGET_HOST, TARGET_USER, ATTACKER_IP, events.LOGON_REMOTE_DESKTOP, SCENARIO)
    )
    return logs

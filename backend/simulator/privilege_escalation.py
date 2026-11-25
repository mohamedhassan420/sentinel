"""Scenario: privilege escalation with a new admin account
(MITRE ATT&CK T1136.001 and T1098).

Working as the victim, the attacker creates a new local account with a dull
name and adds it to the Administrators group. They now own an administrator
account of their own, which still works if the victim changes their password.
"""

import random
from datetime import datetime, timedelta

from backend.models import Log
from backend.simulator import events, noise

SCENARIO = "privilege_escalation"

VICTIM = noise.STAFF[2]  # d.okafor in HR
NEW_ACCOUNT = "svc_update"  # named to pass for a routine service account
NEW_ACCOUNT_SID = "S-1-5-21-1004336348-1177238915-682003330-1009"  # made up
# The built-in Administrators group has this SID on every Windows machine.
ADMINISTRATORS_SID = "S-1-5-32-544"


def generate(end: datetime, rng: random.Random, victim: tuple = VICTIM) -> list[Log]:
    """Return the attack's log lines, finishing at `end`."""
    user, host, _ip = victim
    return [
        events.account_created(end - timedelta(seconds=rng.randint(15, 40)), host, user,
                               NEW_ACCOUNT, NEW_ACCOUNT_SID, SCENARIO),
        events.group_member_added(end, host, user, NEW_ACCOUNT_SID, "Administrators",
                                  ADMINISTRATORS_SID, SCENARIO),
    ]

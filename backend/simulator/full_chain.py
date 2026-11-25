"""Scenario: the full attack chain.

Four of the attacks, in order, against one person on one machine:
phishing -> PowerShell -> privilege escalation -> exfiltration.
Seen one alert at a time they look like separate problems. Together they
are one intrusion, which is what Phase 5's incident timeline will show.
"""

import random
from datetime import datetime, timedelta

from backend.models import Log
from backend.simulator import events, exfiltration, noise, phishing, powershell, privilege_escalation

SCENARIO = "full_chain"

VICTIM = noise.STAFF[0]  # a.khan in finance


def generate(end: datetime, rng: random.Random) -> list[Log]:
    """Return the whole chain's log lines, finishing at `end`.

    Each step finishes the given number of minutes before the end.
    """
    def before_end(minutes: int) -> datetime:
        return end - timedelta(minutes=minutes)

    logs = (
        phishing.generate(before_end(24), rng, VICTIM)
        # The macro in the Word document is what starts PowerShell.
        + powershell.generate(before_end(23), rng, VICTIM, parent_image=events.WINWORD)
        + privilege_escalation.generate(before_end(14), rng, VICTIM)
        + exfiltration.generate(end, rng, VICTIM)
    )
    for log in logs:
        log.scenario = SCENARIO
    return logs

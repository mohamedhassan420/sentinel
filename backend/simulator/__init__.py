"""The attack simulator. It only ever writes text log lines."""

import random
from datetime import datetime, timezone

from backend.models import Log
from backend.simulator import (
    brute_force,
    exfiltration,
    full_chain,
    noise,
    phishing,
    powershell,
    privilege_escalation,
)

# One entry per scenario: its name -> the function that writes its logs.
SCENARIOS = {
    module.SCENARIO: module.generate
    for module in (brute_force, phishing, powershell, privilege_escalation, exfiltration, full_chain)
}


def run(scenario: str, seed: int | None = None) -> list[Log]:
    """Generate one attack mixed into background noise, ending now.

    `seed` makes the random choices repeatable, which the tests rely on.
    """
    rng = random.Random(seed)
    end = datetime.now(timezone.utc)
    return noise.generate(end, rng) + SCENARIOS[scenario](end, rng)

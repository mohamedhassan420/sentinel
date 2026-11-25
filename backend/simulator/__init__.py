"""The attack simulator. It only ever writes text log lines."""

import random
from datetime import datetime, timezone

from backend.models import Log
from backend.simulator import brute_force, noise

# One entry per attack scenario. Phase 2 adds the other four.
SCENARIOS = {
    brute_force.SCENARIO: brute_force.generate,
}


def run(scenario: str, seed: int | None = None) -> list[Log]:
    """Generate one attack mixed into background noise, ending now.

    `seed` makes the random choices repeatable, which the tests rely on.
    """
    rng = random.Random(seed)
    end = datetime.now(timezone.utc)
    return noise.generate(end, rng) + SCENARIOS[scenario](end, rng)

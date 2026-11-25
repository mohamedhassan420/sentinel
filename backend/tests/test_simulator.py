import random
from collections import Counter
from datetime import datetime, timedelta, timezone

from backend.simulator import brute_force, noise

END = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


def test_brute_force_is_40_failures_then_one_success():
    logs = brute_force.generate(END, random.Random(1))
    failures, success = logs[:-1], logs[-1]

    assert len(failures) == 40
    assert all(log.event_id == 4625 for log in failures)
    assert success.event_id == 4624

    # One account, one host, all inside two minutes, success last.
    assert {log.user for log in logs} == {brute_force.TARGET_USER}
    assert {log.host for log in logs} == {brute_force.TARGET_HOST}
    assert all(END - timedelta(minutes=2) <= log.time < END for log in failures)
    assert success.time == END
    assert brute_force.ATTACKER_IP in success.message


def test_noise_looks_normal():
    # Whatever the random seed, noise must stay quiet enough that Phase 2's
    # brute force rule ("many failures on one account") cannot fire on it.
    for seed in range(20):
        logs = noise.generate(END, random.Random(seed))
        assert len(logs) == 60
        assert {log.scenario for log in logs} == {"background"}
        assert {log.event_id for log in logs} <= {4624, 4625, 1}
        assert all(END - timedelta(minutes=30) <= log.time <= END for log in logs)
        failures = Counter(log.user for log in logs if log.event_id == 4625)
        assert max(failures.values(), default=0) < 10

import base64
import random
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from backend import simulator
from backend.engine import detection
from backend.simulator import (
    brute_force,
    events,
    exfiltration,
    full_chain,
    noise,
    phishing,
    powershell,
    privilege_escalation,
)

END = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
RULES = detection.load_rules()


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


# Each scenario imitates the log sources the plan names for it:
# scenario -> the (source, event ID) of each line it writes, in time order.
EXPECTED_LINES = {
    phishing: [("Email Gateway", None), ("Sysmon", 1), ("Sysmon", 1)],
    powershell: [("Sysmon", 1), ("PowerShell", 4104)],
    privilege_escalation: [("Windows Security", 4720), ("Windows Security", 4732)],
    exfiltration: [("Sysmon", 3), ("Firewall", None)],
}


@pytest.mark.parametrize("scenario", EXPECTED_LINES, ids=lambda module: module.SCENARIO)
def test_scenario_writes_the_expected_lines(scenario):
    logs = scenario.generate(END, random.Random(1))
    assert [(log.source, log.event_id) for log in logs] == EXPECTED_LINES[scenario]
    assert {log.scenario for log in logs} == {scenario.SCENARIO}
    assert [log.time for log in logs] == sorted(log.time for log in logs)
    assert logs[-1].time == END


def test_message_is_written_from_the_fields():
    # People read the message and rules read the fields, so they must agree.
    log = phishing.generate(END, random.Random(1))[0]
    for name, value in log.fields.items():
        assert f"{name}: {value}" in log.message


def test_encoded_powershell_command_decodes_to_the_logged_script():
    process, script_block = powershell.generate(END, random.Random(1))
    encoded = process.fields["CommandLine"].split("-EncodedCommand ")[1]
    assert base64.b64decode(encoded).decode("utf-16-le") == script_block.fields["ScriptBlockText"]


def test_exfiltration_sends_about_2_gb_to_the_attacker():
    for seed in range(20):
        firewall = exfiltration.generate(END, random.Random(seed))[-1]
        assert 2_000_000_000 <= firewall.fields["bytes_sent"] <= 2_300_000_000
        assert firewall.fields["dst_ip"] == events.ATTACKER_SERVER


def test_full_chain_is_one_victim_on_one_machine_in_order():
    logs = full_chain.generate(END, random.Random(1))
    user, host, _ip = full_chain.VICTIM

    assert {log.scenario for log in logs} == {"full_chain"}
    assert {log.user for log in logs} == {user}
    # Everything is on the victim's machine except the email, which the mail gateway logs.
    assert {log.host for log in logs} == {host, events.MAIL_GATEWAY_HOST}
    times = [log.time for log in logs]
    assert times == sorted(times)
    assert times[-1] == END
    # No gap longer than 30 minutes, so Phase 5 can link every step into one incident.
    assert all(later - earlier < timedelta(minutes=30) for earlier, later in zip(times, times[1:]))
    # In the chain, the Word macro is what starts PowerShell.
    assert logs[3].fields["Image"] == powershell.POWERSHELL_EXE
    assert logs[3].fields["ParentImage"] == events.WINWORD


def test_noise_looks_normal():
    # Whatever the random seed, noise must stay quiet enough that the brute
    # force rule ("many failures on one account") cannot fire on it.
    for seed in range(20):
        logs = noise.generate(END, random.Random(seed))
        assert len(logs) == 60
        assert {log.scenario for log in logs} == {"background"}
        assert {log.event_id for log in logs} <= {4624, 4625, 1, 4104, None}
        assert all(END - timedelta(minutes=30) <= log.time <= END for log in logs)
        failures = Counter(log.user for log in logs if log.event_id == 4625)
        assert max(failures.values(), default=0) < 10


# ---------------------------------------------------------------- detection
# Phase 2's "done when": every scenario raises the right alerts, and normal
# activity raises none.

# scenario -> the rules that must fire, in the order the attack unfolds.
EXPECTED_ALERTS = {
    "brute_force": [
        "win_security_many_failed_logons",
        "win_security_rdp_logon_from_public_ip",
    ],
    "phishing": [
        "email_macro_attachment_external_sender",
        "proc_creation_win_office_spawns_shell",
    ],
    "powershell": [
        "proc_creation_win_powershell_encoded_command",
        "posh_ps_web_download",
    ],
    "privilege_escalation": [
        "win_security_local_account_created",
        "win_security_user_added_to_local_admins",
    ],
    "exfiltration": [
        "net_connection_win_ftp_to_public_ip",
        "fw_large_upload_to_public_ip",
    ],
    "full_chain": [
        "email_macro_attachment_external_sender",
        "proc_creation_win_office_spawns_shell",  # Word starts cmd.exe
        "proc_creation_win_office_spawns_shell",  # Word starts PowerShell
        "proc_creation_win_powershell_encoded_command",
        "posh_ps_web_download",
        "win_security_local_account_created",
        "win_security_user_added_to_local_admins",
        "net_connection_win_ftp_to_public_ip",
        "fw_large_upload_to_public_ip",
    ],
}


def test_every_scenario_is_checked():
    assert set(EXPECTED_ALERTS) == set(simulator.SCENARIOS)


@pytest.mark.parametrize("scenario", EXPECTED_ALERTS)
def test_scenario_raises_exactly_the_right_alerts(scenario):
    # run() mixes the attack into background noise, as the app does.
    for seed in range(25):
        alerts = detection.detect(simulator.run(scenario, seed), RULES)
        assert [alert.rule_id for alert in alerts] == EXPECTED_ALERTS[scenario]


def test_every_rule_is_fired_by_some_scenario():
    # A rule no scenario can trigger would be dead weight in the demo.
    fired = {rule_id for rule_ids in EXPECTED_ALERTS.values() for rule_id in rule_ids}
    assert fired == {rule.name for rule in RULES}


def test_alerts_point_only_at_attack_logs():
    # The scenario label is the answer key: evidence must never be a background line.
    for scenario in simulator.SCENARIOS:
        logs = simulator.run(scenario, seed=3)
        for number, log in enumerate(logs):
            log.id = number
        for alert in detection.detect(logs, RULES):
            assert {logs[log_id].scenario for log_id in alert.log_ids} == {scenario}


def test_background_noise_raises_no_alerts():
    for seed in range(300):
        assert detection.detect(noise.generate(END, random.Random(seed)), RULES) == []

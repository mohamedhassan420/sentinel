"""How the rule engine itself behaves, tested with small made-up rules."""

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from backend.engine import detection
from backend.models import Log
from backend.simulator import events

T = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)

RULE = """
title: Test Rule
description: A rule made up for a test.
tags: [attack.execution, attack.t1059.001]
logsource: {{product: windows, category: process_creation}}
level: {level}
detection:
{detection}
"""

THRESHOLD_RULE = """
title: Failed Logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Many Failed Logons
description: Five failures in one minute.
tags: [attack.credential_access, attack.t1110]
level: medium
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [TargetUserName]
  timespan: 1m
  condition:
    gte: 5
"""


def load(tmp_path, text: str) -> detection.Rule:
    path = tmp_path / "test_rule.yml"
    path.write_text(text, encoding="utf-8")
    return detection.load_rule(path)


def rule_with(tmp_path, detection_block: str, level: str = "high") -> detection.Rule:
    indented = "\n".join("  " + line for line in detection_block.strip().splitlines())
    return load(tmp_path, RULE.format(level=level, detection=indented))


def process(image: str, command_line: str = "", parent: str = r"C:\Windows\explorer.exe") -> Log:
    return events.process_create(T, "WKS-FIN-03", "a.khan", image, parent, "test", command_line)


def failure(seconds: float, user: str = "s.ahmed") -> Log:
    return events.logon_failure(T + timedelta(seconds=seconds), "SRV-RDP-01", user, "203.0.113.77", 10, "test")


# ------------------------------------------------------------------ modifiers


@pytest.mark.parametrize(
    "modifier, actual, wanted, expected",
    [
        ("equals", "WINWORD.EXE", "winword.exe", True),  # capitals are ignored
        ("equals", 4625, "4625", True),  # a number equals the same number written as text
        ("equals", "winword.exe.bak", "winword.exe", False),
        ("contains", "powershell.exe -ENC abc", " -enc ", True),
        ("contains", "powershell.exe -File a.ps1", " -enc ", False),
        ("startswith", "DC-01", "dc-", True),
        ("startswith", "WKS-DC-01", "DC-", False),
        ("endswith", r"C:\Windows\System32\cmd.exe", r"\cmd.exe", True),
        ("endswith", r"C:\Tools\notcmd.exe", r"\cmd.exe", False),
        ("gte", 2_147_483_648, 1_073_741_824, True),
        ("gte", 1_073_741_824, 1_073_741_824, True),  # "or equal"
        ("gte", 1_073_741_823, 1_073_741_824, False),
        ("gte", "not a number", 5, False),
        ("cidr", "10.0.20.13", "10.0.0.0/8", True),
        ("cidr", "172.31.255.255", "172.16.0.0/12", True),  # the last private address in the range
        ("cidr", "172.32.0.1", "172.16.0.0/12", False),  # the first public one after it
        ("cidr", "203.0.113.77", "10.0.0.0/8", False),
        ("cidr", "not an address", "10.0.0.0/8", False),
    ],
)
def test_modifiers(modifier, actual, wanted, expected):
    assert detection.MODIFIERS[modifier](actual, wanted) is expected


# ----------------------------------------------------------------- selections


def test_a_list_of_values_means_any_of_them(tmp_path):
    rule = rule_with(tmp_path, r"""
selection:
  Image|endswith: ['\cmd.exe', '\powershell.exe']
condition: selection
""")
    assert detection.matches(rule, process(r"C:\Windows\System32\cmd.exe"))
    assert detection.matches(rule, process(r"C:\Windows\System32\powershell.exe"))
    assert not detection.matches(rule, process(r"C:\Windows\System32\notepad.exe"))


def test_every_field_in_a_selection_must_match(tmp_path):
    rule = rule_with(tmp_path, r"""
selection:
  Image|endswith: '\powershell.exe'
  CommandLine|contains: ' -enc '
condition: selection
""")
    assert detection.matches(rule, process(r"C:\powershell.exe", "powershell.exe -enc abc"))
    assert not detection.matches(rule, process(r"C:\powershell.exe", "powershell.exe -File a.ps1"))
    assert not detection.matches(rule, process(r"C:\cmd.exe", "cmd.exe -enc abc"))


def test_a_field_the_log_does_not_have_never_matches(tmp_path):
    rule = rule_with(tmp_path, """
selection:
  ScriptBlockText|contains: ''
condition: selection
""")
    # Every text contains the empty text, so only the missing field can stop this.
    assert not detection.matches(rule, process(r"C:\cmd.exe"))


def test_event_id_and_host_can_be_tested_like_fields(tmp_path):
    rule = rule_with(tmp_path, """
selection:
  EventID: 1
  Computer: wks-fin-03
condition: selection
""")
    assert detection.matches(rule, process(r"C:\cmd.exe"))


def test_logsource_limits_which_logs_a_rule_reads(tmp_path):
    rule = rule_with(tmp_path, r"""
selection:
  Image|endswith: '\ftp.exe'
condition: selection
""")
    ftp = r"C:\Windows\System32\ftp.exe"
    assert detection.matches(rule, process(ftp))
    # Same program, but a network connection (Sysmon 3), not a process start (Sysmon 1).
    assert not detection.matches(
        rule, events.network_connection(T, "WKS-FIN-03", "a.khan", ftp, "10.0.20.13", "198.51.100.23", 21, "test")
    )
    # Same fields and event ID, but written by a different tool.
    from_another_tool = process(ftp)
    from_another_tool.source = "Windows Security"
    assert not detection.matches(rule, from_another_tool)


# ----------------------------------------------------------------- conditions


@pytest.mark.parametrize(
    "condition, expected",
    [
        # For the log below: a is True, b is True, c is False.
        ("a", True),
        ("c", False),
        ("not c", True),
        ("not a", False),
        ("a and b", True),
        ("a and c", False),
        ("a or c", True),
        ("c or c", False),
        ("a and not c", True),
        ("a and not b", False),
        ("a and b and not c", True),
        ("c or a and b", True),  # "and" binds tighter than "or"
        ("(c or a) and c", False),  # brackets change that
        ("not (a and c)", True),
    ],
)
def test_conditions(tmp_path, condition, expected):
    rule = rule_with(tmp_path, rf"""
a:
  Image|endswith: '\cmd.exe'
b:
  CommandLine|contains: whoami
c:
  ParentImage|endswith: '\WINWORD.EXE'
condition: {condition}
""")
    assert detection.matches(rule, process(r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami")) is expected


# ----------------------------------------------------------------- thresholds


def alert_sizes(tmp_path, logs: list[Log]) -> list[int]:
    """How many logs are behind each alert the threshold rule raises."""
    alerts = detection.detect(logs, [load(tmp_path, THRESHOLD_RULE)])
    return [len(alert.log_ids) for alert in alerts]


def test_threshold_is_reached_exactly(tmp_path):
    assert alert_sizes(tmp_path, [failure(i) for i in range(4)]) == []
    assert alert_sizes(tmp_path, [failure(i) for i in range(5)]) == [5]


def test_one_burst_is_one_alert_holding_all_its_logs(tmp_path):
    assert alert_sizes(tmp_path, [failure(i) for i in range(40)]) == [40]


def test_logs_too_far_apart_do_not_add_up(tmp_path):
    # Ten failures, one every 30 seconds: never five inside one minute.
    assert alert_sizes(tmp_path, [failure(i * 30) for i in range(10)]) == []


def test_the_window_edge_is_included(tmp_path):
    # Five failures spanning exactly 60 seconds count; 61 seconds do not.
    assert alert_sizes(tmp_path, [failure(s) for s in (0, 15, 30, 45, 60)]) == [5]
    assert alert_sizes(tmp_path, [failure(s) for s in (0, 15, 30, 45, 61)]) == []


def test_a_burst_is_found_even_after_a_slow_start(tmp_path):
    # Two stray failures, then a real burst an hour later.
    logs = [failure(0), failure(100)] + [failure(3600 + i) for i in range(5)]
    assert alert_sizes(tmp_path, logs) == [5]


def test_each_group_is_counted_separately(tmp_path):
    # Four failures each for two accounts: eight in total, but no account reaches five.
    logs = [failure(i, "s.ahmed") for i in range(4)] + [failure(i, "m.rossi") for i in range(4)]
    assert alert_sizes(tmp_path, logs) == []


def test_two_separate_bursts_are_two_alerts(tmp_path):
    logs = [failure(i) for i in range(5)] + [failure(3600 + i) for i in range(6)]
    assert alert_sizes(tmp_path, logs) == [5, 6]


def test_logs_arriving_out_of_order_are_put_in_time_order_first(tmp_path):
    assert alert_sizes(tmp_path, [failure(i) for i in (4, 1, 3, 0, 2)]) == [5]
    # Four quick failures and one an hour later, which happens to arrive first.
    assert alert_sizes(tmp_path, [failure(i) for i in (3600, 0, 1, 2, 3)]) == []


# --------------------------------------------------------------------- alerts


def test_an_alert_copies_the_rule_and_points_at_its_logs(tmp_path):
    logs = [failure(i) for i in range(5)]
    for number, log in enumerate(logs, start=101):
        log.id = number
    (alert,) = detection.detect(logs, [load(tmp_path, THRESHOLD_RULE)])

    assert alert.rule_id == "test_rule"
    assert alert.title == "Many Failed Logons"
    assert alert.severity == "Medium"
    assert alert.attack_tactics == ["Credential Access"]
    assert alert.attack_techniques == ["T1110"]
    assert (alert.host, alert.user) == ("SRV-RDP-01", "s.ahmed")
    assert alert.log_ids == [101, 102, 103, 104, 105]
    assert alert.time == logs[-1].time
    assert alert.status == "New"


@pytest.mark.parametrize(
    "level, severity", [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]
)
def test_sigma_levels_become_severities(tmp_path, level, severity):
    rule = rule_with(tmp_path, "selection:\n  EventID: 1\ncondition: selection", level=level)
    assert rule.severity == severity


# ------------------------------------------------------- mistakes in rule files

GOOD_RULE = RULE.format(level="high", detection="""\
  selection:
    EventID: 1
  condition: selection""")


def test_the_good_rule_loads(tmp_path):
    # Each broken rule below is this one with a single mistake put in.
    assert load(tmp_path, GOOD_RULE).title == "Test Rule"


@pytest.mark.parametrize(
    "broken_rule, complaint",
    [
        (GOOD_RULE.replace("EventID: 1", "Image|matches: x"), "unknown modifier"),
        (GOOD_RULE.replace("condition: selection", "condition: selection and filter"), "unknown selection in condition"),
        (GOOD_RULE.replace("condition: selection", "condition: 1 of selection*"), "SyntaxError"),
        # A condition is read as a formula, never run as code.
        (GOOD_RULE.replace("condition: selection", "condition: __import__('os').getcwd()"), "may only use and, or, not"),
        (GOOD_RULE.replace("condition: selection", "condition: selection == selection"), "may only use and, or, not"),
        (GOOD_RULE.replace("level: high", "level: urgent"), "unknown level"),
        (GOOD_RULE.replace("process_creation", "dns_query"), "unknown logsource"),
        (GOOD_RULE.replace("attack.execution", "attack.exploding"), "unknown ATT&CK tactic"),
        (GOOD_RULE.replace(", attack.t1059.001", ""), "at least one ATT&CK tactic tag and one technique tag"),
        (GOOD_RULE.replace("level: high", ""), "KeyError('level')"),
        (THRESHOLD_RULE.replace("rules: [failed_logon]", "rules: [something_else]"), "event_count"),
        (THRESHOLD_RULE.replace("timespan: 1m", "timespan: 1w"), "unknown time unit"),
        ("", "IndexError"),  # an empty file
    ],
)
def test_a_broken_rule_file_is_refused_with_a_reason(tmp_path, broken_rule, complaint):
    with pytest.raises(ValueError, match="test_rule.yml is not valid") as error:
        load(tmp_path, broken_rule)
    assert complaint in str(error.value)


# ------------------------------------------------------------- the real rules


def test_the_real_rules_are_complete_and_distinct():
    rules = detection.load_rules()
    assert len(rules) == 10
    assert all(rule.title and rule.description and rule.tactics and rule.techniques for rule in rules)

    # Every Sigma rule carries a unique id, so it can be told apart even if
    # its file is renamed.
    documents = [
        document
        for path in sorted(detection.RULES_DIR.glob("*.yml"))
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
    ]
    ids = [document["id"] for document in documents]
    assert len(ids) == len(set(ids)) == 11  # ten rules, one of them written as two documents

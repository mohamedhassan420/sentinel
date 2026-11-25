"""The detection engine: reads Sigma-style rules and checks logs against them.

Read this file top to bottom:

  1. The lookup tables a rule's words are checked against
  2. What a rule looks like once loaded
  3. Loading the rule files and catching mistakes in them
  4. Matching one log against one rule
  5. Thresholds ("20 failures in 5 minutes")
  6. detect(): logs in, alerts out
"""

import ast
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import yaml

from backend.models import Alert, Log

RULES_DIR = Path(__file__).parent.parent / "rules"


# ---------------------------------------------------------------- 1. Tables

# A Sigma rule says which kind of log it reads in its `logsource` block.
# This table says what each name means inside Sentinel:
#   logsource name -> (the Log.source to read, its event ID or None for any)
# Every SIEM keeps a table like this. Sigma calls it a "pipeline".
LOG_SOURCES = {
    "security": ("Windows Security", None),
    "process_creation": ("Sysmon", 1),
    "network_connection": ("Sysmon", 3),
    "ps_script": ("PowerShell", 4104),
    "firewall": ("Firewall", None),
    "email": ("Email Gateway", None),
}

# Sigma `level` -> the severity shown in the app.
SEVERITIES = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

# The 14 MITRE ATT&CK tactics, in the order an attack usually moves through
# them. A tactic is the attacker's goal; a technique is the method.
TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

# A technique tag looks like attack.t1110, or attack.t1566.001 for a sub-technique.
TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(\.\d{3})?)")

TIME_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def _text(value) -> str:
    # Sigma ignores capitals: "WINWORD.EXE" matches "winword.exe".
    return str(value).lower()


def _at_least(actual, wanted) -> bool:
    try:
        return float(actual) >= float(wanted)
    except (TypeError, ValueError):
        return False  # not a number, so it cannot be "at least" anything


def _in_network(actual, wanted) -> bool:
    # `wanted` is a network range such as 10.0.0.0/8 (CIDR notation).
    try:
        return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(wanted)
    except ValueError:
        return False  # not an IP address, so it is in no network


# The ways a rule can compare a log's value (`actual`) with the rule's value
# (`wanted`). A rule picks one by writing e.g. `Image|endswith`. Writing just
# the field name means "equals".
MODIFIERS = {
    "equals": lambda actual, wanted: _text(actual) == _text(wanted),
    "contains": lambda actual, wanted: _text(wanted) in _text(actual),
    "startswith": lambda actual, wanted: _text(actual).startswith(_text(wanted)),
    "endswith": lambda actual, wanted: _text(actual).endswith(_text(wanted)),
    "gte": _at_least,  # "greater than or equal": for numbers
    "cidr": _in_network,  # for IP addresses
}


# ----------------------------------------------------- 2. A rule, once loaded


@dataclass(frozen=True)
class Check:
    """One line of a selection, e.g. `Image|endswith: '\\cmd.exe'`."""

    field: str
    modifier: str
    values: list  # the check passes if ANY one of these matches


@dataclass(frozen=True)
class Threshold:
    """Fire only when `count` or more matching logs, alike in every
    `group_by` field, fall within `timespan` of each other."""

    group_by: list[str]
    timespan: timedelta
    count: int


@dataclass(frozen=True)
class Rule:
    name: str  # the file name without ".yml"; alerts store it as rule_id
    title: str
    description: str
    severity: str
    tactics: list[str]  # e.g. ["Credential Access"]
    techniques: list[str]  # e.g. ["T1110"]
    source: str  # which Log.source this rule reads
    event_id: int | None  # and which event ID, or None for any
    selections: dict[str, list[Check]]  # name -> checks that must ALL pass
    condition: ast.expr  # how the selections combine, as a parsed tree
    threshold: Threshold | None = None


# ------------------------------------------------------- 3. Loading the files


def load_rules(folder: Path = RULES_DIR) -> list[Rule]:
    """Load every rule file in the folder.

    A mistake in any file raises an error straight away. The app loads the
    rules at startup, so a broken rule stops it there. That is far better
    than a rule that silently never fires.
    """
    return [load_rule(path) for path in sorted(folder.glob("*.yml"))]


def load_rule(path: Path) -> Rule:
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        return _build_rule(path.stem, documents)
    except Exception as problem:
        raise ValueError(f"Rule file {path.name} is not valid: {problem!r}") from problem


def _build_rule(name: str, documents: list[dict]) -> Rule:
    base = documents[0]
    # A threshold rule has a second YAML document holding a `correlation`
    # block. Its title, level and tags are the ones that describe the alert.
    correlation = documents[1] if len(documents) > 1 else None
    about = correlation or base

    logsource = base["logsource"]
    source, event_id = _lookup(LOG_SOURCES, logsource.get("category") or logsource.get("service"), "logsource")

    # In the `detection` block, `condition` is the formula and every other
    # key is a named selection.
    detection = dict(base["detection"])
    condition = detection.pop("condition")
    selections = {key: _parse_selection(value) for key, value in detection.items()}

    tactics, techniques = _parse_tags(about["tags"])
    return Rule(
        name=name,
        title=about["title"],
        description=about["description"].strip(),
        severity=_lookup(SEVERITIES, about["level"], "level"),
        tactics=tactics,
        techniques=techniques,
        source=source,
        event_id=event_id,
        selections=selections,
        condition=_parse_condition(condition, selections),
        threshold=_parse_threshold(correlation["correlation"], base) if correlation else None,
    )


def _lookup(table: dict, key, what: str):
    if key not in table:
        raise ValueError(f"unknown {what} {key!r}; expected one of {sorted(table)}")
    return table[key]


def _parse_selection(selection: dict) -> list[Check]:
    """Turn {"Image|endswith": "\\cmd.exe", ...} into a list of Checks."""
    checks = []
    for key, wanted in selection.items():
        field, _, modifier = key.partition("|")
        modifier = modifier or "equals"
        _lookup(MODIFIERS, modifier, "modifier")
        # One value or a list of values: store both as a list.
        checks.append(Check(field, modifier, wanted if isinstance(wanted, list) else [wanted]))
    return checks


def _parse_condition(condition: str, selections: dict) -> ast.expr:
    """Turn "selection and not filter" into a tree, checking it as we go.

    Sigma conditions use the same words as Python (and, or, not, brackets),
    so Python's own parser can read them. It only reads the text into a tree
    of nodes. Nothing in the condition is ever run as code.
    """
    tree = ast.parse(condition, mode="eval").body
    allowed = (ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.Name, ast.Load)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise ValueError(f"condition {condition!r} may only use and, or, not, brackets and selection names")
        if isinstance(node, ast.Name):
            _lookup(selections, node.id, "selection in condition")
    return tree


def _parse_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Split tags like attack.credential_access and attack.t1110 into
    tactic names and technique IDs."""
    tactics, techniques = [], []
    for tag in tags:
        technique = TECHNIQUE_TAG.fullmatch(tag)
        if technique:
            techniques.append(technique.group(1).upper())
        else:
            tactics.append(_lookup(TACTICS, tag.removeprefix("attack."), "ATT&CK tactic"))
    if not tactics or not techniques:
        raise ValueError("a rule needs at least one ATT&CK tactic tag and one technique tag")
    return tactics, techniques


def _parse_threshold(correlation: dict, base: dict) -> Threshold:
    if correlation["type"] != "event_count" or correlation["rules"] != [base["name"]]:
        raise ValueError("a correlation must be `type: event_count` over the one rule written above it")
    timespan = correlation["timespan"]  # e.g. "5m": a number, then a unit
    return Threshold(
        group_by=correlation["group-by"],
        timespan=timedelta(**{_lookup(TIME_UNITS, timespan[-1], "time unit"): int(timespan[:-1])}),
        count=int(correlation["condition"]["gte"]),
    )


# -------------------------------------------------- 4. One log against a rule


def event_fields(log: Log) -> dict:
    """Everything a rule can test: the log's own fields, plus the event ID
    and host under the names Sigma rules use for them."""
    return {"EventID": log.event_id, "Computer": log.host, **log.fields}


def matches(rule: Rule, log: Log) -> bool:
    """Does this one log satisfy the rule?"""
    # First the logsource: is this even the kind of log the rule reads?
    if log.source != rule.source:
        return False
    if rule.event_id is not None and log.event_id != rule.event_id:
        return False
    # Then the detection: work out True or False for each named selection,
    # and let the condition combine them.
    fields = event_fields(log)
    selected = {
        name: all(_check_passes(check, fields) for check in checks)
        for name, checks in rule.selections.items()
    }
    return _condition_holds(rule.condition, selected)


def _check_passes(check: Check, fields: dict) -> bool:
    if check.field not in fields:
        return False  # the log does not have this field at all
    compare = MODIFIERS[check.modifier]
    return any(compare(fields[check.field], wanted) for wanted in check.values)


def _condition_holds(node: ast.expr, selected: dict[str, bool]) -> bool:
    """Walk the condition tree. `selected` says which selections matched."""
    if isinstance(node, ast.Name):  # a selection's name
        return selected[node.id]
    if isinstance(node, ast.UnaryOp):  # not X
        return not _condition_holds(node.operand, selected)
    # What is left is "X and Y and ..." or "X or Y or ...".
    parts = [_condition_holds(part, selected) for part in node.values]
    return all(parts) if isinstance(node.op, ast.And) else any(parts)


# --------------------------------------------------------------- 5. Thresholds


def _bursts(matching: list[Log], threshold: Threshold) -> list[list[Log]]:
    """Find the bursts: runs of matching logs that reach the threshold.

    `matching` must be in time order. Each burst becomes one alert, so 40
    failed logons raise one alert and not 40.
    """
    # Count separately for each combination of the group-by fields, e.g.
    # each account on each machine.
    groups = defaultdict(list)
    for log in matching:
        fields = event_fields(log)
        groups[tuple(str(fields.get(name)) for name in threshold.group_by)].append(log)

    bursts = []
    for group in groups.values():
        start = 0
        while start < len(group):
            # Everything from this log up to one timespan after it.
            window = [log for log in group[start:] if log.time - group[start].time <= threshold.timespan]
            if len(window) >= threshold.count:
                bursts.append(window)
                start += len(window)  # carry on after the burst
            else:
                start += 1
    return bursts


# ---------------------------------------------------- 6. Logs in, alerts out


def detect(logs: list[Log], rules: list[Rule]) -> list[Alert]:
    """Check every log against every rule and return the alerts to raise."""
    alerts = []
    for rule in rules:
        matching = sorted((log for log in logs if matches(rule, log)), key=lambda log: log.time)
        if rule.threshold is None:
            groups = [[log] for log in matching]  # one alert per matching log
        else:
            groups = _bursts(matching, rule.threshold)
        alerts += [_alert(rule, group) for group in groups]
    return sorted(alerts, key=lambda alert: alert.time)


def _alert(rule: Rule, evidence: list[Log]) -> Alert:
    last = evidence[-1]
    return Alert(
        time=last.time,
        rule_id=rule.name,
        title=rule.title,
        severity=rule.severity,
        attack_tactics=rule.tactics,
        attack_techniques=rule.techniques,
        host=last.host,
        user=last.user,
        log_ids=[log.id for log in evidence],
    )

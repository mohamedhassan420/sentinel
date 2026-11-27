"""Indicators of compromise (IoCs): the searchable facts an attack leaves behind.

An indicator is something concrete from the evidence that a defender can
act on: block the address at the firewall, search every mailbox for the
sender, look for the file on other machines. A report lists them so the next
team can do exactly that.

They are read from the evidence logs of an incident's alerts. Evidence lines
are the ones a rule matched, so what they name is what the attack used.
"""

import ipaddress
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from backend.models import Alert, Indicator, Log

# Which log fields hold which kind of indicator.
FIELD_KINDS = {
    "IpAddress": "IP address",  # Windows logon events: where the logon came from
    "DestinationIp": "IP address",  # Sysmon network connections
    "dst_ip": "IP address",  # firewall sessions
    "sender_domain": "Domain",  # email
    "sender": "Email address",
    "attachment": "File name",
}
# Web addresses can appear inside any text, such as a PowerShell script.
URL = re.compile(r"https?://[^\s'\"<>]+")
# The order the kinds are listed in.
KINDS = ["IP address", "Domain", "URL", "Email address", "File name", "Account created"]

# The company's own address ranges (RFC 1918) and the machine itself. An
# address inside them is one of ours, not an indicator.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
]

# Log text is written partly by the attacker and can be any length.
MAX_LENGTH = 200


def find(alerts: list[Alert], logs: dict[int, Log]) -> list[Indicator]:
    """The indicators in the evidence of these alerts, each one listed once
    with the first alert that shows it. `logs` holds the evidence by log id."""
    found: dict[tuple[str, str], Indicator] = {}
    for alert in alerts:
        for log_id in alert.log_ids:
            if log_id not in logs:
                continue
            for kind, value in _in_log(logs[log_id]):
                value = value[:MAX_LENGTH]
                if not value:
                    continue  # an empty field names nothing
                found.setdefault(
                    (kind, value),
                    Indicator(kind=kind, value=value, alert_id=alert.id, alert_title=alert.title),
                )
    return sorted(found.values(), key=lambda indicator: KINDS.index(indicator.kind))


def _in_log(log: Log) -> Iterator[tuple[str, str]]:
    """Every (kind, value) indicator in one log line."""
    for name, value in log.fields.items():
        kind = FIELD_KINDS.get(name)
        if kind == "IP address":
            if _is_outside(value):
                yield kind, str(value)
        elif kind:
            yield kind, str(value)
        elif isinstance(value, str):
            for url in URL.findall(value):
                yield "URL", url
                yield from _server_of(url)
    # Event 4720 is "a user account was created": the new account is the
    # attacker's way back in.
    if (log.source, log.event_id) == ("Windows Security", 4720) and "TargetUserName" in log.fields:
        yield "Account created", str(log.fields["TargetUserName"])


def _is_outside(value) -> bool:
    """Is this an IP address outside the company network?"""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False  # not an IP address at all
    return not any(address in network for network in INTERNAL_NETWORKS)


def _server_of(url: str) -> Iterator[tuple[str, str]]:
    """The server a web address points to, as an indicator of its own."""
    try:
        server = urlsplit(url).hostname
    except ValueError:
        return  # a malformed address: the URL itself is still listed
    if not server:
        return
    try:
        ipaddress.ip_address(server)
    except ValueError:
        yield "Domain", server
    else:
        if _is_outside(server):
            yield "IP address", server


def defang(indicator: Indicator) -> str:
    """The indicator's value, made safe to print in a report.

    PDF viewers and email programs turn anything that looks like an address
    into a link. Nobody should reach an attacker's server by clicking a
    report, so analysts "defang" addresses: http becomes hxxp and each dot
    becomes [.], which a person can still read but a program will not link.
    """
    if indicator.kind in ("IP address", "Domain", "URL", "Email address"):
        return indicator.value.replace("http", "hxxp", 1).replace(".", "[.]")
    return indicator.value


def defang_text(text: str, indicators: list[Indicator]) -> str:
    """The text with every indicator it mentions defanged, so a summary
    that names the attacker's server is as safe to print as the table."""
    # Longest first: a web address contains its server's address, and must
    # be rewritten whole before the shorter one is looked for.
    for indicator in sorted(indicators, key=lambda indicator: len(indicator.value), reverse=True):
        text = text.replace(indicator.value, defang(indicator))
    return text

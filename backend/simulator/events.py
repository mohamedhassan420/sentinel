"""Builders for the individual log lines the scenarios are made of.

Each function returns one Log in the common format, with the field names
the real tool uses. Nothing here touches a real system: these are text
lines only.
"""

from datetime import datetime

from backend.models import Log

WINDOWS_SECURITY = "Windows Security"
SYSMON = "Sysmon"
POWERSHELL = "PowerShell"
FIREWALL = "Firewall"
EMAIL_GATEWAY = "Email Gateway"

# The fake company. ".example" is a reserved ending (RFC 2606): no address
# under it can ever exist on the real internet.
EMAIL_DOMAIN = "corp.example"
MAIL_GATEWAY_HOST = "MAIL-GW-01"

# The attacker's server in the PowerShell and exfiltration scenarios.
# 198.51.100.0/24 is reserved for documentation and examples (RFC 5737),
# so this address can never belong to a real machine.
ATTACKER_SERVER = "198.51.100.23"

# Windows "logon types" say HOW someone logged on.
LOGON_INTERACTIVE = 2  # at the keyboard
LOGON_NETWORK = 3  # over the network, e.g. opening a shared folder
LOGON_REMOTE_DESKTOP = 10  # through Remote Desktop (RDP)

# Programs the scenarios mention more than once.
EXPLORER = r"C:\Windows\explorer.exe"  # the Windows desktop
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"


def _log(time: datetime, host: str, user: str, source: str, event_id: int | None,
         summary: str, fields: dict, scenario: str) -> Log:
    """Build one Log. The readable message is written from the fields, so
    what a person reads and what a rule tests can never disagree."""
    details = " | ".join(f"{name}: {value}" for name, value in fields.items())
    return Log(time=time, host=host, user=user, source=source, event_id=event_id,
               message=f"{summary} {details}", fields=fields, scenario=scenario)


# ------------------------------------------------------------ Windows Security


def logon_success(time: datetime, host: str, user: str, ip: str, logon_type: int, scenario: str) -> Log:
    """Event 4624: an account logged on."""
    fields = {"TargetUserName": user, "LogonType": logon_type, "IpAddress": ip}
    return _log(time, host, user, WINDOWS_SECURITY, 4624,
                "An account was successfully logged on.", fields, scenario)


def logon_failure(time: datetime, host: str, user: str, ip: str, logon_type: int, scenario: str) -> Log:
    """Event 4625: a logon attempt failed.

    SubStatus 0xC000006A means "the user name is real, the password is wrong".
    """
    fields = {
        "TargetUserName": user,
        "LogonType": logon_type,
        "FailureReason": "Unknown user name or bad password",
        "Status": "0xC000006D",
        "SubStatus": "0xC000006A",
        "IpAddress": ip,
    }
    return _log(time, host, user, WINDOWS_SECURITY, 4625, "An account failed to log on.", fields, scenario)


def account_created(time: datetime, host: str, creator: str, new_account: str, new_sid: str, scenario: str) -> Log:
    """Event 4720: a user account was created.

    "Subject" is who did it and "Target" is the new account. A SID (security
    identifier) is the ID number Windows gives every account and group.
    """
    fields = {
        "SubjectUserName": creator,
        "TargetUserName": new_account,
        "TargetDomainName": host,  # a local account belongs to the machine itself
        "TargetSid": new_sid,
    }
    return _log(time, host, creator, WINDOWS_SECURITY, 4720, "A user account was created.", fields, scenario)


def group_member_added(time: datetime, host: str, adder: str, member_sid: str,
                       group: str, group_sid: str, scenario: str) -> Log:
    """Event 4732: a member was added to a local group.

    Here "Target" is the group. Windows records the new member by SID only;
    for a local account the MemberName field really is just "-".
    """
    fields = {
        "SubjectUserName": adder,
        "MemberName": "-",
        "MemberSid": member_sid,
        "TargetUserName": group,
        "TargetSid": group_sid,
    }
    return _log(time, host, adder, WINDOWS_SECURITY, 4732,
                "A member was added to a security-enabled local group.", fields, scenario)


# ---------------------------------------------------------------------- Sysmon


def process_create(time: datetime, host: str, user: str, image: str, parent_image: str,
                   scenario: str, command_line: str | None = None) -> Log:
    """Sysmon event 1: a program started. "Image" is Sysmon's word for the
    program file, and the parent is the program that started it."""
    fields = {
        "Image": image,
        "CommandLine": command_line or f'"{image}"',
        "ParentImage": parent_image,
        "User": f"CORP\\{user}",
    }
    return _log(time, host, user, SYSMON, 1, "Process Create.", fields, scenario)


def network_connection(time: datetime, host: str, user: str, image: str, source_ip: str,
                       destination_ip: str, destination_port: int, scenario: str) -> Log:
    """Sysmon event 3: a program opened a network connection."""
    fields = {
        "Image": image,
        "User": f"CORP\\{user}",
        "Protocol": "tcp",
        "SourceIp": source_ip,
        "DestinationIp": destination_ip,
        "DestinationPort": destination_port,
    }
    return _log(time, host, user, SYSMON, 3, "Network connection detected.", fields, scenario)


# ------------------------------------------------------------------ PowerShell


def script_block(time: datetime, host: str, user: str, script: str, scenario: str) -> Log:
    """PowerShell event 4104: the text of a script, logged as PowerShell is
    about to run it. Any encoding has already been removed."""
    return _log(time, host, user, POWERSHELL, 4104, "Creating Scriptblock text (1 of 1).",
                {"ScriptBlockText": script}, scenario)


# ------------------------------------------------- Firewall and email gateway
# Neither numbers its events the way Windows does, so event_id is empty.


def firewall_session(time: datetime, host: str, user: str, source_ip: str, destination_ip: str,
                     destination_port: int, bytes_sent: int, bytes_received: int, scenario: str) -> Log:
    """One finished connection through the company firewall, written when it
    closes. The firewall only sees addresses; a SIEM looks up which machine
    and user had that address, which is why host and user are filled in."""
    fields = {
        "action": "allow",
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "dst_port": destination_port,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
    }
    return _log(time, host, user, FIREWALL, None, "Connection closed.", fields, scenario)


def email_delivered(time: datetime, recipient: str, sender: str, subject: str,
                    attachment: str | None, scenario: str) -> Log:
    """The mail gateway delivered a message to a member of staff."""
    fields = {
        "action": "delivered",
        "sender": sender,
        "sender_domain": sender.split("@")[1],
        "recipient": f"{recipient}@{EMAIL_DOMAIN}",
        "subject": subject,
    }
    if attachment:
        fields["attachment"] = attachment
    return _log(time, MAIL_GATEWAY_HOST, recipient, EMAIL_GATEWAY, None, "Message delivered.", fields, scenario)

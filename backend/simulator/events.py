"""Builders for the individual log lines the scenarios are made of.

Each function returns one Log in the common format, with a message written
the way the real tool words it. Nothing here touches a real system: these
are text lines only.
"""

from datetime import datetime

from backend.models import Log

WINDOWS_SECURITY = "Windows Security"
SYSMON = "Sysmon"

# Windows "logon types" say HOW someone logged on.
LOGON_INTERACTIVE = 2  # at the keyboard
LOGON_NETWORK = 3  # over the network, e.g. opening a shared folder
LOGON_REMOTE_DESKTOP = 10  # through Remote Desktop (RDP)


def logon_success(time: datetime, host: str, user: str, ip: str, logon_type: int, scenario: str) -> Log:
    """Windows Security event 4624: an account logged on."""
    message = (
        "An account was successfully logged on. "
        f"Account Name: {user} | Logon Type: {logon_type} | "
        f"Workstation Name: {host} | Source Network Address: {ip}"
    )
    return Log(time=time, host=host, user=user, source=WINDOWS_SECURITY,
               event_id=4624, message=message, scenario=scenario)


def logon_failure(time: datetime, host: str, user: str, ip: str, logon_type: int, scenario: str) -> Log:
    """Windows Security event 4625: a logon attempt failed.

    Sub Status 0xC000006A means "the user name is real, the password is wrong".
    """
    message = (
        "An account failed to log on. "
        f"Account Name: {user} | Logon Type: {logon_type} | "
        "Failure Reason: Unknown user name or bad password | "
        "Status: 0xC000006D | Sub Status: 0xC000006A | "
        f"Workstation Name: {host} | Source Network Address: {ip}"
    )
    return Log(time=time, host=host, user=user, source=WINDOWS_SECURITY,
               event_id=4625, message=message, scenario=scenario)


def process_create(time: datetime, host: str, user: str, image: str, parent_image: str, scenario: str) -> Log:
    """Sysmon event 1: a program started. "Image" is Sysmon's word for the program file."""
    message = (
        "Process Create. "
        f"Image: {image} | CommandLine: \"{image}\" | "
        f"ParentImage: {parent_image} | User: CORP\\{user}"
    )
    return Log(time=time, host=host, user=user, source=SYSMON,
               event_id=1, message=message, scenario=scenario)

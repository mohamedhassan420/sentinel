# Sentinel

[![CI](https://github.com/mohamedhassan420/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/mohamedhassan420/sentinel/actions/workflows/ci.yml)

An AI-assisted SOC triage tool. It simulates attacks as log lines, detects them with Sigma-style rules mapped to MITRE ATT&CK, and turns the alerts into incident timelines and reports.

**Status: Phase 3 of 6.** The simulator writes five attacks and a full attack chain, ten Sigma-style rules detect them, and each match becomes an alert tagged with its MITRE ATT&CK technique. A dashboard shows what is waiting, the alert queue tracks each alert from New to Closed, and every rule has a plain-English Explain page. AI triage, incidents and reports come in later phases (the dashboard's count of open incidents arrives with them). The full plan is in [docs/PLAN.md](docs/PLAN.md).

Nothing here attacks anything. The simulator only writes text log lines into a local database.

## Run it

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```
docker compose up --build
```

Then open http://localhost:8000. The API's own documentation page is at http://localhost:8000/docs.

1. On the **Dashboard**, pick a scenario and press **Run scenario**. The open-alert counts and the ATT&CK strip update.
2. Open **Alerts** and select an alert. Its page shows why the rule fired, the log lines that are the evidence, and a status you can change: New, In progress, Closed as true positive or Closed as false positive.
3. Select **Read how this rule works** for the rule's Explain page: what the attack is, what the log shows, why the rule catches it, and the Security+ topic it connects to. **Detections** lists all ten.
4. **Logs** shows every line the simulator wrote, attack and background alike.

To stop, press Ctrl+C in that terminal. To also delete the stored logs and alerts, run `docker compose down -v`.

## Detection rules

The rules are YAML files in [backend/rules](backend/rules), written in the [Sigma](https://sigmahq.io/) format. A small engine in [backend/engine/detection.py](backend/engine/detection.py) reads them and checks every new log.

| Scenario | Rule | Severity | ATT&CK |
| --- | --- | --- | --- |
| Brute force login | Many Failed Logons For One Account | Medium | T1110 |
| | Remote Desktop Logon From A Public IP Address | High | T1133, T1078 |
| Phishing | Macro-Enabled Office Attachment From An External Sender | Medium | T1566.001 |
| | Office Application Starts A Command Shell | High | T1204.002 |
| Malicious PowerShell | PowerShell Started With An Encoded Command | High | T1059.001, T1027.010 |
| | PowerShell Script Downloads From The Web | Medium | T1059.001, T1105 |
| Privilege escalation | Local User Account Created | Low | T1136.001 |
| | User Added To The Local Administrators Group | High | T1098 |
| Data exfiltration | FTP Connection To A Public IP Address | Medium | T1048.003 |
| | Large Upload To A Public IP Address | High | T1048 |

The full attack chain runs phishing, PowerShell, privilege escalation and exfiltration on one machine and raises nine alerts.

Each rule has an Explain page in the app. Its text is a file of the same name in [backend/explain](backend/explain), and the app will not start if a rule is missing one.

Every rule is tested both ways: logs that must fire it, and harmless look-alikes that must not. Another test runs 300 random half hours of normal office activity through all ten rules and expects no alerts.

The engine supports the parts of Sigma these rules need: field checks with `contains`, `startswith`, `endswith`, `gte` and `cidr`, conditions with `and`, `or` and `not`, and `event_count` correlations (a count over a time window). The email rule uses a log source name of its own, because Sigma has no standard one for mail gateways.

## Develop

Backend (Python 3.12), from the project root:

```
py -3.12 -m venv backend/.venv
backend/.venv/Scripts/pip install -r backend/requirements-dev.txt
backend/.venv/Scripts/pytest backend
backend/.venv/Scripts/uvicorn backend.main:app --reload
```

Frontend (Node 24), in a second terminal:

```
cd frontend
npm ci
npm run dev
```

The frontend dev server on http://localhost:5173 passes `/api` requests to the backend on port 8000.

## Layout

```
backend/
  main.py         the API
  models.py       the database tables (logs and alerts) and the shapes of the API's answers
  simulator/      background noise and one file per attack scenario
  rules/          the detection rules, one Sigma-style YAML file each
  explain/        the Explain mode text, one file per rule
  engine/         the rule engine that checks logs against the rules
  tests/
frontend/         the React dashboard
docs/             plan, decisions and learning notes
```

## Next steps

Ideas outside the current phase are parked here until Phase 6 is done.

- A note and an analyst's name on each status change, so the queue records who decided what and why.
- Sorting the alert queue by severity as well as by time.
- A chart of alerts over time on the dashboard. The plan's chart library (Recharts) is not installed yet: today's dashboard is counts and a strip, which plain HTML and CSS draw.
- A rule for password spraying (one password tried against many accounts). The brute force rule counts per account, so spraying slips under it.
- Link-preview tags (Open Graph) for when the site goes public in Phase 6.
- The High and Medium severity colours (orange and yellow) are close. They always carry their word, but consider moving them further apart in the Phase 6 UI review.
- A "Clear logs" button, so a demo can start from an empty table without `docker compose down -v`.
- An off-hours check. The plan has the exfiltration happen at 3 AM, but the simulator stamps every scenario "just now" so new lines appear at the top. The upload is detected by its size, whatever the hour.
- A rule for "a successful logon straight after a burst of failures". It needs Sigma's `temporal` correlation type, which the engine does not support yet.
- Detection over a sliding time window. Today the rules check each new batch of logs on its own, so a burst split across two batches would be missed.
- Run the rules through `sigma-cli` to convert them into Splunk or Elastic queries (the plan's stretch goal).
- Paging through logs older than the newest 200.
- `npm audit` reports 4 moderate issues in `minimatch`, pulled in by the `shadcn` command-line tool. It is used only while building and is not shipped to the browser. Recheck in the Phase 6 security scan.
- Starlette's test client now prefers `httpx2` over `httpx` (a deprecation warning in the test run). Switch once that is settled.

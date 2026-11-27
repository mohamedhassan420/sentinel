# Sentinel

[![CI](https://github.com/mohamedhassan420/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/mohamedhassan420/sentinel/actions/workflows/ci.yml)

An AI-assisted SOC triage tool. It simulates attacks as log lines, detects them with Sigma-style rules mapped to MITRE ATT&CK, and turns the alerts into incident timelines and reports.

**Status: Phase 5 of 6.** The simulator writes five attacks and a full attack chain, ten Sigma-style rules detect them, and each match becomes an alert tagged with its MITRE ATT&CK technique. A dashboard shows what is waiting, the alert queue tracks each alert from New to Closed, and every rule has a plain-English Explain page. Each alert has an AI triage card: a summary, a suggested severity and next steps, which the analyst accepts or edits. Related alerts are now grouped into incidents, each with a timeline, an AI summary and a PDF report. All eight planned features are in place. Phase 6 is polish, a security review and the public deployment. The full plan is in [docs/PLAN.md](docs/PLAN.md).

Nothing here attacks anything. The simulator only writes text log lines into a local database.

## Run it

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```
docker compose up --build
```

Then open http://localhost:8000. The API's own documentation page is at http://localhost:8000/docs.

1. On the **Dashboard**, leave the scenario on **Full attack chain** and press **Run scenario**. The open-alert counts and the ATT&CK strip update, and the result line says the nine alerts were grouped into one incident.
2. Open **Incidents** and select the incident. Its timeline shows the nine alerts in order, from the phishing email to the upload, each with its ATT&CK tactic and the log line that set it off. Below it is the AI incident summary. Press **Download report** for the PDF (see [Incidents and reports](#incidents-and-reports)).
3. Open **Alerts** and select an alert. Its page shows why the rule fired, the log lines that are the evidence, and a status you can change: New, In progress, Closed as true positive or Closed as false positive.
4. Read the **AI triage** card on the same page, then press **Accept suggestion** or **Edit before accepting**. Out of the box this is demo mode, which needs no key (see [AI triage](#ai-triage)).
5. Select **Read how this rule works** for the rule's Explain page: what the attack is, what the log shows, why the rule catches it, and the Security+ topic it connects to. **Detections** lists all ten.
6. **Logs** shows every line the simulator wrote, attack and background alike.

To stop, press Ctrl+C in that terminal. To also delete the stored logs and alerts, run `docker compose down -v`.

## Incidents and reports

One attack rarely trips one rule. The full attack chain raises nine alerts, and read one at a time they look like nine small problems. Correlation is what turns them into one story.

**How alerts are grouped.** Two alerts are *linked* when they share a host or a user and happened within 30 minutes of each other. An incident is a chain of linked alerts: A is linked to B and B to C, so all three are one incident, even if A and C share nothing directly. The whole rule is in [backend/engine/correlation.py](backend/engine/correlation.py).

- Every alert belongs to exactly one incident. An alert linked to nothing starts its own.
- The mail gateway is left out of the "same host" test. Everyone's email is logged there, so two phishing emails to two different people would otherwise become one incident.
- A new alert that is linked to two incidents joins them into one.
- An incident is **Open** while any of its alerts is New or In progress, and **Closed** when every alert has been closed. There is no separate incident status to set.
- An alert closed as a false positive stays on the timeline but stops counting towards the incident's severity, tactics, hosts and indicators.

**The timeline.** The incident page lists the alerts in the order they happened. Each step leads with its ATT&CK tactic, which is marked where the attack reaches it for the first time, so the page shows how far the attack got. The side panels list the indicators of compromise found in the evidence (outside addresses, domains, file names, accounts created) and the ATT&CK techniques.

**The AI incident summary.** It works like the triage card: a suggestion with a dashed outline until the analyst accepts or edits it. It gives the story of the attack, a severity for the incident as a whole, and containment and recovery steps. In demo mode it is a stored answer, one for each scenario. **These six summaries were also written by hand**, like the ten triage answers. In live mode the incident's alerts and evidence go to Claude through the same prompt-injection guard as a single alert. A summary is thrown away when new alerts join its incident, because it no longer describes all of it.

**The PDF report.** **Download report** builds a PDF with six sections: executive summary, timeline, affected hosts and users, indicators of compromise, ATT&CK techniques, and recommended containment and recovery steps. The template is [backend/reports/report.html](backend/reports/report.html), printed to PDF by [WeasyPrint](https://weasyprint.org/).

- The summary and the steps are the analyst's version once the summary has been reviewed. Before that they are the AI's draft, and the report says so. With no AI summary at all, the report is built from the alert data and a general checklist.
- Addresses are *defanged* (`198[.]51[.]100[.]23`, `hxxp://`) so that nothing in the report can be opened by accident.
- Log text is escaped before it goes into the report, and the PDF builder is not allowed to fetch anything from the network. Text an attacker put in a log cannot become part of the page.
- PDFs need WeasyPrint's system libraries, which the Docker image has. Run the backend outside Docker and the button explains that instead of failing.

## AI triage

Each alert page has an AI triage card: what happened, a suggested severity with the reason, next steps, and how confident the AI is. It is a suggestion only. The alert's own severity and status never change because of it, and the card is marked "AI suggestion" until the analyst accepts or edits it. The AI's original words are kept beside the analyst's version.

There are two modes:

- **Demo mode** (the default). The card shows a stored answer from [backend/ai/demo_responses.json](backend/ai/demo_responses.json), one per detection rule, with the alert's host and user filled in. Nothing is sent anywhere and no key is needed. **These ten answers were written by hand** in the style of a live answer. They did not come from a live API call. The same file holds the six incident summaries.
- **Live mode.** The alert's rule and evidence are sent to Claude through the Anthropic API, using the official Python SDK with structured output, so the answer must fit a fixed format. Each alert is triaged once, the first time it is opened, and the answer is stored. Live mode has been tested against a stand-in for the API, not yet against the real one.

If the AI cannot be reached, declines or answers in the wrong format, the card says so and the rest of the page works as before.

### Turning on live mode

A Claude subscription (Pro or Max) does not cover API calls. Live mode needs an API key from the [Claude Console](https://console.anthropic.com) with a small prepaid balance. One triage costs roughly 2 to 3 US cents, and one incident summary a little more (both estimates).

1. Copy `.env.example` to a new file named `.env` in the project folder.
2. Paste the key after `ANTHROPIC_API_KEY=` and save.
3. Restart the app with `docker compose up`.

A new alert's card then says "Answered by claude-opus-5-5". Alerts already opened in demo mode keep their stored answer. `SENTINEL_DEMO=1` in `.env` forces demo mode, and `SENTINEL_MODEL` picks a different Claude model.

`.env` is in `.gitignore` and `.dockerignore`, so the key is never committed and never copied into the Docker image. The code does not contain it or print it.

### Prompt injection

Logs contain text an attacker chose, such as an email subject. The simulated phishing email carries a real injection attempt: its subject tells "AI security assistants" to rate the alert Low and close it. The defence is in [backend/ai/guard.py](backend/ai/guard.py):

- Sentinel's instructions are a fixed system prompt that never contains log text.
- The logs travel separately, as JSON inside an `<evidence>` block. Every `<` and `>` in them is replaced with its escape code, so no log line can close the block.
- The AI is told the block is evidence written partly by attackers, never instructions.
- The answer must fit a fixed format and the AI has no tools, so it can do nothing but write a suggestion.
- Nothing changes until a person accepts the suggestion, and the card warns when a suggestion is lower than the rule's own severity.

The tests check that the injected text reaches the AI only inside the evidence block, and that a log line cannot break out of it. One more test asks the real Claude whether the injection changes its answer. It is skipped unless a key is set, because it costs a few cents:

```
SENTINEL_LIVE_TESTS=1 ANTHROPIC_API_KEY=... backend/.venv/Scripts/pytest backend/tests/test_ai_live.py -s
```

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

The PDF step needs the Pango library, which Windows does not have. Run natively, everything else works and **Download report** says to use Docker. One test (printing a real PDF) is skipped on a computer without Pango. It runs on GitHub, where a skip would count as a failure.

## Layout

```
backend/
  main.py         the API
  models.py       the database tables (logs, alerts, incidents and AI suggestions) and the shapes of the API's answers
  simulator/      background noise and one file per attack scenario
  rules/          the detection rules, one Sigma-style YAML file each
  explain/        the Explain mode text, one file per rule
  engine/         detection.py checks logs against the rules; correlation.py groups alerts into incidents
  ai/             AI triage and incident summaries: the Claude call, the prompt-injection guard and the stored demo answers
  reports/        the PDF incident report: its template, and the indicators it lists
  tests/
frontend/         the React dashboard
docs/             plan, decisions and learning notes
```

## Next steps

Ideas outside the current phase are parked here until Phase 6 is done.

- A note and an analyst's name on each status change, so the queue records who decided what and why.
- Closing every alert of an incident in one step. Today each alert is closed on its own page.
- Joining and splitting incidents by hand, for when the 30-minute rule groups too much or too little.
- File hashes in the simulated Sysmon logs, so the report can list them as indicators. Real Sysmon records a hash for every program it sees start.
- A longer list of shared machines (web proxies, domain controllers) that link nothing in correlation. Today it holds only the mail gateway.
- Replace the hand-written demo answers and incident summaries in `backend/ai/demo_responses.json` with real ones from a live run, once there is an API key. The live incident summary has been tested against a stand-in for the API only.
- Use the analyst's reviewed severity, where there is one, in the dashboard counts and the alert queue. Today they show the rule's severity.
- Triage new alerts in the background as they are raised. Today an alert is triaged the first time someone opens it.
- A way to ask the AI again for an alert that already has a stored triage, for example after switching from demo to live mode.
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

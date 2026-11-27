# Sentinel: AI SOC Analyst Assistant — Spec & Build Plan

**Project owner:** Mohamed Hassan · Plan dated 25 Nov 2026 · Live copy: https://claude.ai/artifact/4nGPwQfxZvZ8VRFEMxauWK

## Overview

Sentinel is a web app that plays the role of a junior SOC analyst's assistant. It generates realistic attack logs, catches them with detection rules, and uses AI to explain each alert and write the incident report. It is built in 6 phases, and each phase ends with something working that Mohamed can demo and explain.

**The one-line pitch for a CV:** *"Built Sentinel, an AI-assisted SOC triage tool that simulates five attack scenarios, detects them with Sigma-style rules mapped to MITRE ATT&CK, and auto-generates incident timelines and PDF reports."*

**Who it is for:**

- **Recruiters and interviewers**, who get the GitHub link (it runs with one Docker command), a clean README and a 2-minute video.
- **Mohamed**, who learns the blue-team workflow (logs → detection → triage → report) that Security+ and SOC analyst roles test.

**Why it works as a portfolio piece:**

- It shows the real SOC loop end to end, not just one tool.
- It needs no home lab, VMs or real malware. The attack logs are simulated, so it is safe and anyone can run it.
- It uses AI the way SOC teams are starting to: to speed up triage, with a human still deciding.
- Every detection has an "Explain mode" page, so Mohamed can talk through any feature in plain English.

**How the work is split:** Claude builds all the code. Mohamed reads the "What Mohamed learns" box at the end of each phase, tries the feature in the app, and can explain it before the next phase starts.

## Features

Version 1 has exactly 8 features, all required. Anything not on this list waits until after Phase 6.

| # | Feature | What it does, in plain English |
| --- | --- | --- |
| 1 | Attack simulator | Press a button and Sentinel writes realistic fake logs for one of 5 attacks, mixed in with normal "background" activity. |
| 2 | Detection engine | Reads every log and checks it against detection rules written in Sigma-style YAML. A match creates an alert. |
| 3 | MITRE ATT&CK mapping | Every rule and alert is tagged with its ATT&CK tactic and technique ID, and the dashboard shows which techniques fired. |
| 4 | AI triage | For each alert, the AI explains what happened, suggests a severity (Low to Critical) with a reason, and lists next steps. The analyst can accept or change it. |
| 5 | Incident timeline | Groups related alerts (same host or user, close in time) into one incident and shows them in order, like a story of the attack. |
| 6 | PDF incident report | One click turns an incident into a report: summary, timeline, affected assets, ATT&CK techniques, recommended actions. |
| 7 | Explain mode | A plain-English page per detection: what the attack is, what the log shows, why the rule catches it, and the linked Security+ concept. |
| 8 | Dashboard | Home screen with alert counts by severity, open incidents, an ATT&CK heat strip, and a "Run a scenario" button. |

### The 5 simulated attacks

Each scenario produces logs in the same formats real tools produce, so the detections are realistic.

| Scenario | What the fake logs show | Log source it imitates | ATT&CK technique | Security+ link |
| --- | --- | --- | --- | --- |
| Brute force login | 40 failed logins on one account in 2 minutes, then one success | Windows Security events 4625 (failed) and 4624 (success) | T1110 Brute Force | Password attacks, account lockout policy |
| Phishing | An email with a lookalike sender domain and a macro attachment, then Word starting a child process | Email gateway log + Sysmon event 1 (process create) | T1566.001 Spearphishing Attachment | Social engineering, email security |
| Malicious PowerShell | PowerShell run with an encoded command that downloads a file | PowerShell event 4104 (script block) + Sysmon event 1 | T1059.001 PowerShell | Malicious code indicators, scripting |
| Privilege escalation | A new local account is created and added to the Administrators group | Windows Security events 4720 and 4732 | T1136.001 Create Local Account, T1098 Account Manipulation | Least privilege, account management |
| Data exfiltration | A workstation sends 2 GB to an unknown external IP at 3 AM | Firewall / proxy log + Sysmon event 3 (network connection) | T1048 Exfiltration Over Alternative Protocol | Data loss prevention, network monitoring |

The simulator can also run a **"full attack chain"**: phishing → PowerShell → privilege escalation → exfiltration on the same host. This is the best demo, because the timeline shows one incident built from four alerts.

### What the AI does and does not do

- **Does:** explain alerts, suggest severity, summarise incidents, draft the report text.
- **Does not:** decide anything on its own. Every AI output is labelled "AI suggestion" and the analyst clicks to accept or edit it. AI speeds up triage; a human stays accountable.
- **Works without AI too:** detections, timeline and report all work with no API key. The AI adds the written explanations on top.

## Tech stack

| Layer | Choice | Why this one (what to say in an interview) |
| --- | --- | --- |
| Backend language | Python 3.12 | The main language of security tooling, automation and SOAR scripts. |
| Web API | FastAPI | Small, fast, and generates its own API docs page at `/docs`, which is handy in a demo. |
| Detection rules | Sigma-style YAML + a small rule engine written in Python | Sigma is the open, vendor-neutral rule format SOC teams share. Writing a mini engine shows Mohamed understands how detections actually match logs. |
| Rule portability (stretch) | sigma-cli | Converts the same rules into Splunk or Elastic queries, proving they are real Sigma. |
| Database | SQLite (via SQLModel) | One file, zero setup. Easy to swap for PostgreSQL later. |
| AI | Anthropic Claude API, Python SDK, model `claude-opus-5-5` (one config value) | Structured output gives clean JSON for severity and next steps. Roughly 2 cents per alert triaged (estimate). |
| PDF reports | WeasyPrint (HTML → PDF) | The report is designed as a web page, then printed to PDF. |
| Frontend | React + TypeScript + Vite | The most common frontend stack in job ads. |
| Styling and parts | Tailwind CSS + shadcn/ui + Recharts | Clean, consistent components and charts. |
| Tests | pytest + one sample log per rule that must fire, and one that must not | Rules are tested against true and false positives. |
| Packaging | Docker | One command runs the whole app on any machine. |
| Hosting | None. Runs locally with `docker compose up --build` | Every free host needs a card (decided 27 Nov 2026). |
| Automation | GitHub Actions | Runs the tests on every change; green "passing" badge in the README. |

**Two settings that protect Mohamed:**

- **Demo mode (default with no key).** AI answers are pre-generated and stored, so anyone can try every feature without an API key or any cost.
- **Live mode (local, or with Mohamed's own key).** Calls Claude for real. The key lives only in an environment variable, never in the code or on GitHub.
- **The API key is separate from a Claude subscription.** A Max plan does not cover the app's API calls. Live mode needs a key from the Claude Console with a small prepaid balance; demo mode needs nothing.

## Architecture

One Python backend moves data through six stages, plus one React dashboard that shows each stage. The whole app runs in a single Docker container.

```
Attack simulator ──► Log store ──► Detection engine ──► Alerts ◄──────────┐
(5 scenarios+noise)  (SQLite)      (Sigma-style rules)   (ATT&CK tags)    │
                                                           │              │
                                             grouped by host or user      │
                                                           ▼              │
                                    PDF report ◄──── Incidents            │
                                                    (timeline of alerts)  │
                                                           ▲              │
                                             explains and rates severity  │
                                                           │              │
   React dashboard (shows every stage via FastAPI)     AI triage (Claude API)
```

The AI sits beside the pipeline and adds explanations to alerts and incidents. It never changes the data itself.

### What is stored

| Table | Holds | Key fields |
| --- | --- | --- |
| logs | Every simulated log line | time, host, user, source, event_id, message, scenario |
| alerts | One row per rule match | rule_id, severity, attack_technique, log_ids, status |
| incidents | A group of related alerts | alert_ids, hosts, users, start_time, end_time, status |
| triage | AI suggestions | alert_id or incident_id, summary, severity, next_steps, accepted_by_analyst |

Rules are not stored in the database. Each one is a YAML file in a `rules/` folder, so they read like real Sigma rules on GitHub.

### Project folders

```
sentinel/
  backend/
    simulator/      # one file per attack scenario
    rules/          # Sigma-style YAML rules
    engine/         # rule matching and correlation
    ai/             # Claude triage and the prompt-injection guard
    reports/        # PDF template
    tests/          # one pass and one fail log per rule
  frontend/         # React dashboard
  docs/             # PLAN.md, KICKOFF.md, LEARNING.md, DECISIONS.md, interview prep, screenshots
  Dockerfile
  README.md
  CLAUDE.md
```

## Build plan: 6 phases

Each phase ends with a working app Mohamed can open and click through. Mohamed does not move to the next phase until they can answer that phase's three check questions out loud.

### Model and effort per phase

Quality comes first on the Max plan: every build phase runs on Claude Fable 5.2. At the start of each phase, Claude says which model and effort to use and waits for Mohamed to switch.

| Phase | Model | Effort |
| --- | --- | --- |
| Setup (kickoff) | Claude Fable 5.2 | High |
| 1. Foundations and first attack | Claude Fable 5.2 | High |
| 2. Detection engine and all 5 attacks | Claude Fable 5.2 | xhigh |
| 3. Dashboard, alert queue, Explain mode | Claude Fable 5.2 | High |
| 4. AI triage | Claude Fable 5.2 | xhigh |
| 5. Incident timeline and PDF report | Claude Fable 5.2 | xhigh |
| 6. Polish and ship | Claude Fable 5.2 | High, then xhigh for the security scan |
| Small asks between phases | Claude Fable 5.2 | Medium |

If Fable's share of the weekly limit runs out, use Claude Opus 5.5 at xhigh until it resets.

### Phase 1: Foundations and the first attack

**Goal:** the app runs, generates logs, and shows them in a table.

- Build: the GitHub repo, the FastAPI backend, the React frontend shell, Docker setup (`docker compose up` runs everything), and GitHub Actions running tests.
- Build: the common log format (time, host, user, source, event ID, raw message) and the background-noise generator (normal logins, normal processes).
- Build: the first scenario, brute force login.
- **Done when:** one command starts the app, "Run brute force" adds logs, and the logs page shows them with filters.

**What Mohamed learns**

- What a log is, and the main log sources a SOC watches: Windows Security, Sysmon, firewall, email gateway.
- Windows event IDs 4624 (logon success) and 4625 (logon failure), and what "normal" looks like.
- Check questions: *What is the difference between a log and an alert? Why do we generate background noise? What does event 4625 tell you?*

### Phase 2: Detection engine and all 5 attacks

**Goal:** Sentinel catches every simulated attack and ignores normal activity.

- Build: the other 4 scenarios and the full attack chain.
- Build: the rule engine, which reads Sigma-style YAML rules and supports field matching (equals, contains, ends with) and simple thresholds ("more than 20 failures in 5 minutes").
- Build: about 8 to 10 rules, each tagged with its ATT&CK tactic and technique, plus tests that each rule fires on attack logs and stays quiet on normal logs.
- **Done when:** running any scenario creates the right alerts, and all tests pass.

**What Mohamed learns**

- The parts of a Sigma rule: `logsource`, `detection`, `condition`, `level`, `tags`.
- True positive, false positive, false negative, and why rules are tested both ways.
- MITRE ATT&CK: tactics are the attacker's goal (why), techniques are the method (how).
- Check questions: *Walk me through one of your rules. What would cause a false positive? What is the difference between a tactic and a technique?*

### Phase 3: Dashboard, alert queue and Explain mode

**Goal:** it looks and feels like a real SOC tool.

- Build: the dashboard (alert counts by severity, open incidents, ATT&CK techniques seen) and the alert queue with statuses: New, In progress, Closed as true positive, Closed as false positive.
- Build: one Explain mode page per rule, written for a beginner, with a "Security+ connection" box.
- **Done when:** a visitor can run a scenario from the dashboard, open an alert, and read why it fired.

**What Mohamed learns**

- The alert triage workflow: is it real, how bad is it, what is affected, who needs to know.
- How severity is judged: impact on confidentiality, integrity and availability, plus how likely the attack is to succeed.
- Check questions: *What do you do first when a new alert arrives? Why is "Closed as false positive" useful data? Pick one alert and explain it as you would to a manager.*

### Phase 4: AI triage

**Goal:** each alert gets an AI-written explanation, suggested severity and next steps, which the analyst can accept or edit.

- Build: the AI service using the Claude API with structured output (summary, severity, reason, next steps, confidence).
- Build: a safety layer that treats all log text as untrusted data, so a log line saying "ignore your instructions" cannot steer the AI. One simulated phishing email carries exactly this trick, as a test.
- Build: demo mode with stored AI answers, and the "AI suggestion" label with Accept / Edit buttons.
- **Done when:** every alert shows an AI triage card in under 10 seconds in live mode, and instantly in demo mode.

**What Mohamed learns**

- Where AI helps a SOC (speed, consistent write-ups, less alert fatigue) and where it must not decide alone.
- Prompt injection: attackers can hide instructions inside data that an AI reads.
- Keeping secrets out of code: API keys live in environment variables.
- Check questions: *Why is the AI only a suggestion? What is prompt injection, and how does Sentinel defend against it? Where is the API key stored?*

### Phase 5: Incident timeline and PDF report

**Goal:** related alerts become one incident with a clear story and a report a manager could read.

- Build: correlation that groups alerts sharing a host or user within a 30-minute window into one incident.
- Build: the timeline view (events in order, with ATT&CK tactic labels showing how the attack progressed).
- Build: the PDF report: executive summary, timeline, affected hosts and users, indicators, ATT&CK techniques, recommended containment and recovery steps.
- **Done when:** running the full attack chain produces one incident with 4 or more alerts, and "Download report" gives a clean PDF.

**What Mohamed learns**

- The incident response steps Security+ tests: preparation, detection, analysis, containment, eradication, recovery, lessons learned.
- Why correlation matters: four small alerts can be one serious attack.
- Indicators of compromise (IP addresses, file hashes, domains) and how a report communicates them.
- Check questions: *How does Sentinel decide alerts belong together? Which IR step does each report section support? What would you contain first in the full attack chain?*

### Phase 6: Polish and ship

**Goal:** a README that sells it, and Mohamed ready to present it.

- Build: a UI review pass at phone and desktop sizes, empty and loading states, and an "About" page.
- Build: the README, the demo video script, the interview prep page, and a LinkedIn post draft.
- Build: a security scan and threat model of Sentinel's own code before it goes public.
- Mohamed does: records the demo video (about 2 minutes) using the script, and practises the interview prep answers.
- **Done when:** `docker compose up --build` works from a fresh clone, the README has screenshots and a passing-tests badge, and Mohamed can give the 60-second pitch without notes.

**What Mohamed learns**

- How to explain the architecture in one minute and the design trade-offs (simulated data, AI as assistant, demo mode).
- Check questions: *Why did you simulate logs instead of using a real lab? What would you add next? What was the hardest part?*

## Deliverables for the CV (written in Phase 6)

### 1. README

1. Title, one-line pitch, and badges (tests passing, licence).
2. A 10-second GIF of the full attack chain turning into one incident.
3. "What it does" in 5 bullets, then 3 screenshots: dashboard, alert with AI triage, incident timeline.
4. Architecture diagram and the tech stack table.
5. Detection coverage table: every rule, its ATT&CK technique, and its test status.
6. "Run it yourself" in 3 commands (Docker).
7. Security notes: demo mode, how the API key is kept safe, prompt injection defence.
8. What I learned, and what I would build next.

### 2. Demo video script (about 2 minutes)

| Time | On screen | What Mohamed says (summary) |
| --- | --- | --- |
| 0:00–0:15 | Dashboard | "Sentinel is an AI-assisted SOC tool I built to practise the analyst workflow without a home lab." |
| 0:15–0:35 | Click "Run full attack chain" | "This simulates a phishing email leading to PowerShell, a new admin account, and data leaving the network." |
| 0:35–1:00 | Alert queue, open the PowerShell alert | "My Sigma-style rule caught an encoded PowerShell command. It maps to ATT&CK T1059.001." |
| 1:00–1:20 | AI triage card | "The AI explains the alert and suggests a severity. I stay in control: I accept or change it." |
| 1:20–1:40 | Incident timeline | "Four alerts on one host are grouped into one incident, so the attack reads as a story." |
| 1:40–1:55 | Download the PDF report | "One click gives a report with the timeline, indicators and containment steps." |
| 1:55–2:00 | GitHub page | "The code is linked below; it runs with one Docker command." |

### 3. Interview prep one-pager (`docs/INTERVIEW_PREP.md`)

- **The 60-second pitch:** problem, what Sentinel does, one thing Mohamed is proud of.
- **The architecture in one breath:** "Simulator writes logs, the rule engine turns matches into alerts, correlation groups them into incidents, the AI adds explanations, and the report sums it up."
- **8 likely questions with short answers**, for example: *Why simulate logs? How do your rules avoid false positives? Why is the AI not making the final call? What is prompt injection? How does this map to Security+? What would you change for a real company?*
- **5 terms to use naturally:** true positive, false positive, ATT&CK technique, correlation, containment.

### 4. LinkedIn post

About 150 words with the demo GIF: what was built, three things learned, a link to GitHub. Written in Mohamed's voice, honest that AI helped build it and that Mohamed designed, tested and can explain it.

## Recommended plugins and skills

| Add-on | What it adds | When it is used |
| --- | --- | --- |
| Taste Skill (`design-taste-frontend`, github.com/Leonxlnx/taste-skill) | Strong rules against "AI-looking" design | Phases 3 and 6: public-facing pages, README visuals |
| frontend-design (Anthropic) | Polished interface building | Every screen |
| UI Design Review (UXKIN) | Reviews the rendered app on phone and desktop | Phases 3 and 6 |
| Claude Security plugin (Anthropic) | Scans Sentinel's own code, builds a threat model | Phase 6, before going public |
| GitHub | Repo, commits, pull requests | Phase 1 onward |

Taste was written mainly for marketing sites. It leads on public-facing pages; frontend-design leads on the dense dashboard.

## Rules for the builder

1. **No real attacks.** The simulator only writes text log lines. No malware, no exploit code, no scanning of real systems.
2. **Explainable over clever.** Plain code with comments a beginner can follow, especially in the rule engine.
3. **Every rule has two tests:** one log that must trigger it and one that must not.
4. **Secrets stay secret.** The API key lives in an environment variable; `.env` is never committed.
5. **Log text is untrusted.** It is passed to the AI as data, never as instructions.
6. **The app works without AI.** If the AI is unavailable or declines, the alert still shows the rule's own explanation.
7. **Scope is frozen** at the 8 features above until Phase 6 is done.
8. **A learning note per phase** in `docs/LEARNING.md`.

## Risks and fallbacks

| Risk | Fallback |
| --- | --- |
| Someone without a key cannot try the AI | Demo mode with stored answers is the default when there is no key |
| No hosted demo, so recruiters must run Docker to try it | The README's GIF and screenshots, and the demo video, show it working |
| The AI declines some security text | The app still works without AI, and the request falls back to another model |
| The project grows too big to finish | Frozen scope; extras go on a "Next steps" list in the README |
| Mohamed cannot explain a part in an interview | Check questions at the end of each phase, plus `LEARNING.md` |

## Glossary

| Term | Meaning |
| --- | --- |
| SOC | Security Operations Centre: the team that watches for and responds to attacks |
| SIEM | The tool that collects logs and raises alerts (Splunk, Microsoft Sentinel, Elastic) |
| Sigma | An open format for writing detection rules once and using them in any SIEM |
| MITRE ATT&CK | A public catalogue of attacker goals (tactics) and methods (techniques) |
| Triage | Deciding quickly if an alert is real and how urgent it is |
| True / false positive | An alert that is a real attack / an alert on harmless activity |
| Correlation | Linking separate alerts that belong to the same attack |
| IoC | Indicator of compromise: evidence such as a bad IP, domain or file hash |
| Prompt injection | Hiding instructions inside data so an AI that reads it misbehaves |

*Naming note:* Microsoft also sells a SIEM called "Microsoft Sentinel". Alternatives: "Sentry Desk" or "Triage Lens". Decide before the repo is created.

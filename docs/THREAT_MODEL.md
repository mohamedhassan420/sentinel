# Sentinel: Threat model

A threat model is a written answer to four questions: what are we building, what can go wrong, what are we doing about it, and what are we choosing to live with. This one covers Sentinel itself, not the simulated attacks it detects.

**Status, 27 November 2026.** This is a manual review: Claude read every backend file and the frontend's data paths, and fixed what it found (see "Fixed in Phase 6"). The automated scan by the Claude Security plugin then ran on the backend. It found no High or Critical issues, and 3 Medium and 3 Low ones. The Medium ones are fixed. All six are listed in the review log at the end.

## What is being protected

| Asset | Why it matters |
| --- | --- |
| The Claude API key and the credit behind it | Live mode only. A leaked or abused key spends Mohamed's money. |
| The analyst's trust in the screen | If log text can change what the AI says, or what the page shows, the tool misleads the person it is meant to help. |
| The visitor's browser | A page that runs an attacker's script can do anything the visitor can. |
| The app staying up | Anyone who runs it, or ever hosts it, needs it to keep working. |
| The code and its build | A poisoned dependency ships with everything else. |

There are no user accounts, passwords or personal data. Every log line is simulated.

## Who might attack it

1. **A stranger on the network.** Sentinel is not hosted publicly, but it is built as if it were. It has no login, so anyone, including automated scanners, can call every API route.
2. **The attacker inside the logs.** In a real SOC part of every log is written by the attacker: an email subject, a file name, a command line. Sentinel treats all log text as hostile, and one simulated phishing email carries a real prompt-injection attempt to prove the point.
3. **Another website in the owner's browser.** While Sentinel runs on `localhost`, any site open in another tab can make the browser send it requests.
4. **A compromised dependency** on PyPI or npm.

## Where trust changes hands

```
browser on this computer ──► localhost:8000 ──► one container: FastAPI + SQLite file
                                                   │
        log text (untrusted) ──► page, PDF, AI     └──► Anthropic API (live mode only,
                                                        only with a key in .env)
```

The three places untrusted text crosses into something that could act on it are the web page, the PDF report and the AI prompt. Each has its own defence below.

## Threats and defences

| # | Threat | Defence | Where |
| --- | --- | --- | --- |
| 1 | **Prompt injection.** Log text tells the AI to lower a severity or close the alert. | Instructions and logs travel separately; logs sit in an `<evidence>` block they cannot close; the AI is told the block is evidence; its answer must fit a fixed shape and it has no tools; nothing changes until a person accepts, and a suggestion below the rule's severity carries a warning. | `backend/ai/guard.py`, `backend/models.py`, tests in `test_ai.py` |
| 2 | **Cross-site scripting (XSS).** Log text runs as script in the page. | React shows all log text as plain text; the code never builds HTML from data. A Content Security Policy is the second layer: the browser runs no script that did not come from Sentinel's own files. | `frontend/src`, `backend/main.py` |
| 3 | **HTML injection into the PDF.** Log text becomes a tag in the report and makes the server fetch an address or read a file. | The template escapes everything; the PDF builder may load only the font files beside the template and nothing from the network. | `backend/reports/report.py` |
| 4 | **The API key leaks.** | It lives only in the `ANTHROPIC_API_KEY` environment variable. `.env` is in `.gitignore` and `.dockerignore`, the code never logs or returns it, and the git history has been searched for keys. Without a key the app runs in demo mode. | `.gitignore`, `backend/ai/triage.py` |
| 5 | **Someone else spends the AI credit.** | There is no hosted copy holding a key. Locally, Docker publishes the app to this computer only; each alert is triaged once and stored; each request has a token limit and carries at most 50 log lines; and writes set off by another website are refused. | `compose.yaml`, `backend/main.py`, `backend/ai/guard.py` |
| 6 | **Cross-site request forgery (CSRF).** A website the owner visits makes their browser run scenarios or request triages on `localhost`. | Every request that changes data is refused unless the browser says it came from Sentinel's own page (the `Sec-Fetch-Site` header). | `backend/main.py` |
| 7 | **Filling the disk or exhausting the server.** | The log store is emptied when it reaches 20,000 lines; every filter and list has a length or size limit; one PDF is built at a time; one AI answer is worked out at a time. | `backend/main.py` |
| 8 | **SQL injection.** | Every query goes through SQLModel with bound parameters; search text is escaped so `%` and `_` match literally; numbers are range-checked. | `backend/main.py` |
| 9 | **Tampering with evidence.** | The API can change an alert's status and the analyst's review, and nothing else. Logs, alerts and the AI's original words cannot be edited. Status and severity accept only their fixed values. | `backend/main.py`, `backend/models.py` |
| 10 | **Reading other files through a rule name.** | The name is looked up among the rules loaded at startup and is never used to open a file. | `backend/main.py`, `test_api.py` |
| 11 | **A hostile rule file.** | Rules are read with YAML's safe loader. A rule's condition is parsed into a tree and checked against a short allow-list; it is never run as code. | `backend/engine/detection.py` |
| 12 | **Clickjacking.** Another site shows Sentinel in a hidden frame and tricks the visitor into pressing its buttons. | The app forbids being framed. | `backend/main.py` |
| 13 | **A vulnerable or poisoned dependency.** | Python packages are pinned to exact versions and npm packages by a lock file. `pip-audit` and `npm audit` both report no known vulnerabilities (27 Nov 2026). The container runs as an ordinary user, and the GitHub workflow has read-only access to the repo. | `backend/requirements.txt`, `frontend/package-lock.json`, `Dockerfile`, `.github/workflows/ci.yml` |

## Fixed in Phase 6

The manual review found these, and they are fixed and tested:

- **No limit on stored data.** Anyone could run scenarios until the disk filled, and the dashboard reads every alert, so it slowed down with them. The store now empties itself at 20,000 log lines.
- **PDFs could be requested without limit.** Each one costs memory and processor time. Now one is built at a time, and a request that arrives meanwhile is told to try again. (The first version made it wait up to 15 seconds; the plugin scan showed that waiting was itself a weakness, finding F2.)
- **Another website could write to a local Sentinel** (threat 6), and in live mode spend credit through it. Cross-site writes are now refused.
- **No security headers.** Added: a Content Security Policy, no framing, no content-type guessing, no referrer, HTTPS-only once HTTPS has been used. The server no longer announces its name.
- **Four moderate advisories** in a package used only while building the frontend. Updated; `npm audit` is clean.

## Accepted risks

Things left as they are, on purpose, with the reason.

| Risk | Why it is accepted |
| --- | --- |
| **No login.** Anyone can run scenarios, change statuses and edit AI text for anyone who can reach it. | It runs on the owner's computer only, and it is a sandbox of simulated data. A login would only get in the way. A real deployment needs accounts and roles first. |
| **Visitors share one store.** Text one visitor types into an edited summary is shown to the next. | The text is escaped and length-limited, so it cannot run or grow. Locally the only visitor is the owner; it lasts until the store fills. |
| **No rate limit per visitor.** | The host's own network protection is the only brake. The limits in threat 7 bound what a flood can do, and the worst outcome is a restart with an empty store. |
| **Browsers from before 2023 get no CSRF protection**, and neither does an attack that points a hostile domain name at `localhost` (DNS rebinding). | Both need the owner to be running live mode and browsing a hostile site at the same time, and the damage is capped by the prepaid balance. The fix is a check of the `Origin` and `Host` headers. |
| **The API's documentation page (`/docs`) is public** and loads its script from a public library host. | It documents an API that is public anyway, and it is useful in a demo. It shows no log text. |
| **Packages that Sentinel's packages depend on are not pinned by hash**, and base images are pinned by name, not by fingerprint. | Standard for a project this size. A real deployment would pin both and scan the image. |

## What a real company would add

Single sign-on and roles (analyst, lead, read-only); a record of who changed which status and when; rate limits and request-size limits at the proxy; the key in a secrets manager with a spending cap; a database with backups; and central logging of Sentinel's own activity, so the SOC tool is itself monitored.

## Review log

| Date | What | Result |
| --- | --- | --- |
| 27 Nov 2026 | Manual code review by Claude (all backend files, frontend data paths, Docker, CI) | 5 findings, all fixed (above) |
| 27 Nov 2026 | `pip-audit` on `backend/requirements.txt` | No known vulnerabilities |
| 27 Nov 2026 | `npm audit` on the frontend | 4 moderate, fixed by `npm audit fix`; now 0 |
| 27 Nov 2026 | Search of the git history for API keys | None found |
| 27 Nov 2026 | Claude Security plugin scan of `backend/` (medium effort, commit `ce94f41`, every finding checked by an independent verifier panel) | 6 findings: 0 Critical, 0 High, 3 Medium, 3 Low. The 3 Medium ones are fixed (below) |

### Findings from the plugin scan

None is High or Critical. All are about availability, or about spending API credit in local live mode. Each fix has a test that fails without it.

| # | Severity | Finding | State |
| --- | --- | --- | --- |
| F1 | Medium | No request body size limit. One huge JSON body sent to a `PATCH` route is read whole into memory and can restart the free instance. | **Fixed:** bodies over 64 KB get "413 Content Too Large" before they are read |
| F2 | Medium | PDF requests waiting for the one-at-a-time lock keep a database connection and a worker thread for up to 15 s. About 15 parallel requests then stall the whole API. | **Fixed:** the lock is taken first, and a busy server refuses at once instead of queuing |
| F3 | Medium | Repeated `full_chain` runs merge into one incident of thousands of alerts, and each PDF of it is very slow to build. | **Fixed:** the timeline and indicator tables stop at 100 rows each, with a note counting the rest |
| F4 | Low | The cross-site check trusts `Sec-Fetch-Site` only. DNS rebinding, or an old browser, can drive a local live-mode Sentinel. | Allow-list the `Host` header, and require `Origin` on writes |
| F5 | Low | The incident summary prompt has no cap on the number of alerts, so its cost grows with the incident. | Cap the alerts block at 50, like the evidence lines |
| F6 | Low | Live AI calls have no overall rate limit, and failures are retried, so each `POST` can bill again. | A per-minute cap on live calls, and a spending cap on the key in the Console |

F4 to F6 are open, by decision. They need live mode on the owner's own computer, and Sentinel is not hosted anywhere. Their suggested fixes are in the table.

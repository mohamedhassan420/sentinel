# CLAUDE.md: Sentinel

Claude Code reads this file at the start of every session in this folder. Read it in full, then read `docs/PLAN.md`, before doing any work.

## Who you are working with

- **Owner:** Mohamed Hassan, a final-year student studying for CompTIA Security+ and aiming for blue-team / SOC analyst roles. Beginner level.
- **Mohamed does not write code.** You build everything. Mohamed must still be able to explain every part of Sentinel in a job interview, so teaching is part of the job.
- Talk to Mohamed in plain English and explain each technical term the first time you use it. Whenever Mohamed has to do something (install a tool, approve a prompt, click a button, set a key), give exact numbered steps for their operating system. Check the OS yourself rather than asking.
- Keep replies short: what you did, what Mohamed should look at, what comes next.

## The project

Sentinel is an AI-assisted SOC triage web app for Mohamed's CV and LinkedIn. The full spec is in `docs/PLAN.md`. It covers the 8 features, the 5 simulated attacks with their ATT&CK IDs, the architecture, the data model, the 6 build phases, the deliverables, the rules and the risks. `docs/PLAN.md` is the source of truth. An online copy is at https://claude.ai/artifact/4nGPwQfxZvZ8VRFEMxauWK. If the two copies disagree, ask Mohamed which one wins.

## Folder layout

```
sentinel/
  CLAUDE.md          # this brief
  docs/
    PLAN.md          # the full spec and build plan
    KICKOFF.md       # the first-session setup message (kept for reference)
    LEARNING.md      # one plain-English entry per phase
    DECISIONS.md     # short log of decisions Mohamed makes
    THREAT_MODEL.md  # what could go wrong with Sentinel itself, and what stops it
    INTERVIEW_PREP.md  DEMO_SCRIPT.md  LINKEDIN_POST.md   # the CV deliverables
    screenshots/     # the README's images
  backend/  frontend/  ...   # created in Phase 1, as shown in PLAN.md
```

Keep the project root tidy: no stray scripts, temp files or duplicate docs. When Mohamed makes a decision (a name, a colour scheme, a host), add one dated line to `docs/DECISIONS.md`.

## How to work: one phase at a time

Mohamed starts each phase with "Build Phase N". For each phase:

0. **Model check first.** Before anything else, look up the phase in the table below and reply with only this: the recommended model and effort level, the model and effort this session is running on (if you can tell), and the exact steps to switch in the desktop app if they differ. Then wait. Start the phase only when Mohamed confirms the switch or says "go".
1. Re-read that phase in `docs/PLAN.md`. Tell Mohamed in 3 to 5 bullets what you are about to build.
2. Create a git branch named `phase-N-<short-name>`.
3. Build only what that phase lists. If something outside the phase looks useful, add it to "Next steps" in the README instead of building it.
4. Run the tests and the app. Fix anything broken before calling the phase done.
5. Check the phase's **Done when** line yourself, then tell Mohamed exactly what to open and click to see it working.
6. Add a half-page plain-English entry to `docs/LEARNING.md`: what was built, why it works this way, and the phase's "What Mohamed learns" points with short model answers to its 3 check questions.
7. Commit with clear messages and push. Open a pull request for the phase. Once its GitHub checks pass, merge it yourself (`gh pr merge --merge --delete-branch`), then switch to `main` and pull. Never merge while a check is failing or still running. If the checks are still running when you finish, say so and merge at the start of your next turn. (GitHub's built-in auto-merge is unavailable while the repo is private on the free plan. If the repo becomes public or Mohamed gets GitHub Pro, turn on auto-merge with required checks and use that instead.)
8. Stop. Do not start the next phase until Mohamed asks.

## Model and effort per phase

Mohamed is on the Claude Max plan, so quality comes first: every build phase runs on the strongest model. Never suggest a weaker model just to save usage.

| Phase | Model | Effort | Why |
| --- | --- | --- | --- |
| Setup (kickoff) | Claude Fable 5.2 | High | Folder setup, plugins and checks: straightforward, but it sets up everything after it |
| 1. Foundations and first attack | Claude Fable 5.2 | High | Project skeleton, Docker and CI: getting the base right saves pain later |
| 2. Detection engine and all 5 attacks | Claude Fable 5.2 | xhigh | The core security logic: rule matching, thresholds and tests must be exactly right |
| 3. Dashboard, alert queue, Explain mode | Claude Fable 5.2 | High | Mostly UI and writing. The design plugins carry the polish |
| 4. AI triage | Claude Fable 5.2 | xhigh | Claude API integration, structured output and the prompt-injection defence: subtle and security-critical |
| 5. Incident timeline and PDF report | Claude Fable 5.2 | xhigh | Correlation logic and a polished report with many moving parts |
| 6. Polish and ship | Claude Fable 5.2 | High, then xhigh for the security scan | Review, deploy and writing at High; the self-security review deserves the most thinking |
| Small asks between phases (a question, a typo, "explain this file") | Claude Fable 5.2 | Medium | Quick answers; no need to wait for deep thinking |

**If Fable's share of the weekly limit runs out** (Fable can use up to half of the Max plan's weekly limit), say so and recommend **Claude Opus 5.5 at xhigh** for the rest of that week instead of waiting. Raise the effort to compensate; never go below High on a build phase.

## Tech stack (do not swap without asking)

- **Backend:** Python 3.12, FastAPI, SQLModel on SQLite, WeasyPrint for PDFs, pytest.
- **Detection:** Sigma-style YAML rules in `backend/rules/`, matched by a small, readable Python engine in `backend/engine/`. Support field equals / contains / endswith / startswith, a `condition` with and / or / not over named selections, and count thresholds over a time window. Each rule carries ATT&CK tags (for example `attack.t1110`, `attack.credential_access`). Map Sigma `level` values to the app's severities: low → Low, medium → Medium, high → High, critical → Critical.
- **Frontend:** React + TypeScript + Vite, Tailwind CSS, shadcn/ui, Recharts, lucide icons.
- **AI:** the official `anthropic` Python SDK. Model `claude-opus-5-5`, read from the env var `SENTINEL_MODEL` with that as the default. Use structured outputs (`output_config.format` with a JSON schema) for the triage result: summary, severity, severity_reason, next_steps, confidence. Check `stop_reason` before reading content. On `"refusal"` or any error, fall back to the rule's own explanation. Read the claude-api skill or the official docs before writing SDK code, and never guess parameter names.
- **Running locally:** run the app through Docker (`docker compose up`) so Mohamed never has to install WeasyPrint's system libraries by hand. Native Python and Node are for your development and tests.
- **Delivery:** one Docker image serving the API and the built frontend. GitHub Actions runs pytest and the frontend build on every push. There is no public deployment: every free host needs a card. Sentinel runs locally with `docker compose up --build`.

## The API key (important for Mohamed)

Mohamed's Claude Max subscription does **not** cover API calls from the app. Live AI triage needs a separate API key from the Claude Console (console.anthropic.com) with a small prepaid balance. When you reach Phase 4, explain this with exact steps. Until then, and whenever there is no key, the app runs in demo mode.

## Non-negotiable rules

1. **No real attacks.** The simulator writes text log lines only: no malware, no exploit code, no scanning, no contact with real systems.
2. **Explainable over clever.** Short functions, clear names, and comments a beginner can follow, especially in the rule engine and correlation.
3. **Every rule has two tests:** a log that must fire it and a log that must not.
4. **Secrets stay secret.** The key lives only in `ANTHROPIC_API_KEY` in a local `.env`. `.env` is in `.gitignore` from the very first commit, and `.env.example` holds no real values. Never print, log or commit the key.
5. **Log text is untrusted.** When logs go to the AI, wrap them as clearly delimited data and tell the model to treat them as evidence, never as instructions. One phishing log line deliberately contains an injection attempt, and a test proves it does not change the triage result.
6. **The app works without AI.** A missing key, an AI error or a refusal must never break a page.
7. **Demo mode** (`SENTINEL_DEMO=1`, and automatic when there is no key) serves stored AI answers from `backend/ai/demo_responses.json` and never calls the API. Generate that file by running live mode once if Mohamed has a key; otherwise write realistic answers by hand and label them in the README.
8. **Scope is frozen** at the 8 features in the plan until Phase 6 is done.

## UI quality

The app must not look generic or "AI-made". It should look like a calm, professional security tool.

- Use the **frontend-design** skill for every screen.
- Use **Taste Skill** (`design-taste-frontend`) for the public-facing pages (landing / About) and the README visuals.
- Pick one restrained theme with a small set of design tokens: background, surface, border, text, muted text, one accent, and severity colours for Low / Medium / High / Critical. Dark is typical for SOC tools. Use one font family, consistent spacing and real icons, and no emoji in the UI.
- Every view has empty, loading and error states. Check layouts at phone and desktop widths.
- Use **UI Design Review** in Phases 3 and 6 to review the rendered screens.

## Security of Sentinel itself

Sentinel is a security project, so it must be secure itself. Validate all API inputs, escape any log text shown in the UI, and pin dependency versions. In Phase 6, run the **Claude Security** plugin (threat model and scan), fix what it finds, and summarise the results in the README's security notes.

## Open decision

The name "Sentinel" may clash with "Microsoft Sentinel". If `docs/DECISIONS.md` does not settle it, ask Mohamed before creating the GitHub repo (alternatives so far: Sentry Desk, Triage Lens). If the name changes, update this file, `docs/PLAN.md` and the README.

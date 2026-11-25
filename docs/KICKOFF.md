# Sentinel: first-session kickoff

**Before you start:**
1. Make sure `CLAUDE.md`, `PLAN.md` and `KICKOFF.md` are in your Downloads folder.
2. Create one new, empty folder for the project, for example `Documents/sentinel`.
3. In the Claude desktop app, open the **Code** tab and choose that empty folder. Set the model to **Claude Fable 5.2** and the effort to **High**.
4. Paste everything between the two lines below as your first message.
5. When Claude Code asks for permission to read your Downloads folder or to run a command, read what it says and approve it.

---

Hi! I'm Mohamed. This empty folder is for my project **Sentinel**. I don't code, so please explain things simply and give me exact steps whenever I need to do something. Today is setup only. Do these steps in order and stop after step 6.

**1. Prepare the folder and clean up.**
- Find these files in my Downloads folder: `CLAUDE.md`, `PLAN.md` and `KICKOFF.md`. If there are several copies (for example `CLAUDE (1).md`), use the newest one of each, and tell me which ones you picked.
- Move them into this project folder like this:
  - `CLAUDE.md` goes in the project root.
  - `PLAN.md` goes in `docs/PLAN.md`.
  - `KICKOFF.md` goes in `docs/KICKOFF.md`.
- Create `docs/LEARNING.md` (title only) and `docs/DECISIONS.md` (title only).
- Create a `.gitignore` that already ignores `.env`, `node_modules/`, `__pycache__/`, `.venv/`, `*.db` and `dist/`.
- Then delete any leftover copies of those three files from Downloads. Don't touch anything else in Downloads.
- Show me the final folder tree.

**2. Read the brief.** Read `CLAUDE.md` and `docs/PLAN.md` in full and follow them from now on. In 3 bullets, tell me what you understood about the project and how we'll work.

**3. Install the plugins.** Try these yourself in the terminal:
- `claude plugin marketplace add Leonxlnx/taste-skill`
- `claude plugin install taste-skill@taste-skill`
- `claude plugin install frontend-design@claude-plugins-official`
- `claude plugin install github@claude-plugins-official`
- `claude plugin install claude-security@claude-plugins-official`

If a name doesn't match, find the right one in the marketplace listing. If you can't install something yourself, give me the exact `/plugin` command to type. "UI Design Review" comes from my claude.ai account, so just remind me to click Install on it there. Finish by telling me which plugins are installed and whether I need to restart the session for them to load.

**4. Check my computer.** Check for git, Python 3.12, Node.js 20 or newer, and Docker Desktop. For anything missing, give me step-by-step install instructions for my operating system and wait until I say it's done.

**5. Settle the name and GitHub.**
- "Sentinel" clashes with Microsoft Sentinel. Ask whether I want to keep it or pick another name. Record my answer in `docs/DECISIONS.md` and update the files if the name changes.
- Check whether GitHub is connected. If it is, ask me before creating a public repo, then initialise git and push these files. If it isn't, tell me how to connect it.

**6. Wrap up.** In 5 bullets, tell me what's ready and what to type to start Phase 1.

---

## After setup

Open the same folder in the Code tab each time and type:

> Build Phase 1 of the Sentinel plan.

Then Phase 2, and so on. Before each phase starts, Claude tells you which model and effort level to switch to, and waits for you to say "go". After each phase:
1. Try the app the way Claude tells you.
2. Read the new entry in `docs/LEARNING.md`.
3. Make sure you can answer the phase's 3 check questions out loud before moving on.

Live AI triage (Phase 4) needs a separate Claude API key with a small prepaid balance. Your Max plan doesn't cover it. Claude will walk you through it when you get there, and the app works in demo mode without it.

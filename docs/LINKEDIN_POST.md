# Sentinel: LinkedIn post draft

A draft of about 150 words. Change anything that does not sound like you. Before posting, attach the demo video (or `docs/screenshots/full-attack-chain.gif` until the video is recorded).

---

I built Sentinel, an AI-assisted SOC triage tool, as my final-year portfolio project while studying for Security+.

It simulates five attacks as log lines, detects them with ten Sigma-style rules mapped to MITRE ATT&CK, and groups the alerts into one incident with a timeline and a PDF report. Nothing real is attacked.

Three things I learned:

1. Detection is a trade-off. Every rule is tested against the attack and against harmless look-alikes, because a noisy rule gets ignored.
2. Correlation matters. Nine small alerts on one machine in half an hour are one serious attack.
3. AI should assist, not decide. It suggests a severity and the analyst accepts or edits it. One simulated phishing email even tries to talk the AI into closing the alert.

I built it with Claude Code: the AI wrote the code to my plan, and I tested every phase and can explain every part.

Runs locally with one command: docker compose up
Code: https://github.com/mohamedhassan420/sentinel

#SOC #BlueTeam #SecurityPlus #DetectionEngineering

---

## Posting checklist

1. The GitHub repo is public, and the link opens in a private browser window.
2. The GitHub link opens in a private browser window, which shows the repo is public.
3. The video or GIF is attached to the post itself, not just linked.
4. You have read the post out loud once, and it sounds like you.

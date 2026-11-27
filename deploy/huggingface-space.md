---
title: Sentinel
colorFrom: gray
colorTo: green
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: AI-assisted SOC triage on simulated attack logs
---

# Sentinel

The public demo of Sentinel, an AI-assisted SOC triage app. It is a portfolio project: run a simulated attack, watch the detection rules raise alerts, read the AI's triage, and download an incident report.

This Space runs in **demo mode**. The AI answers are stored examples, and no AI service is contacted. Nothing here attacks anything: the simulator only writes text log lines into a database that empties when the Space restarts.

The source code, tests and documentation are on GitHub. This Space is published there automatically after the tests pass; do not edit it here.

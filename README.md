# Sentinel

[![CI](https://github.com/mohamedhassan420/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/mohamedhassan420/sentinel/actions/workflows/ci.yml)

An AI-assisted SOC triage tool. It simulates attacks as log lines, detects them with Sigma-style rules mapped to MITRE ATT&CK, and turns the alerts into incident timelines and reports.

**Status: Phase 1 of 6.** The app runs, the brute force scenario writes logs, and the Logs page shows them with filters. Detection, AI triage, incidents and reports come in later phases. The full plan is in [docs/PLAN.md](docs/PLAN.md).

Nothing here attacks anything. The simulator only writes text log lines into a local database.

## Run it

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```
docker compose up --build
```

Then open http://localhost:8000 and press **Run brute force**. The API's own documentation page is at http://localhost:8000/docs.

To stop, press Ctrl+C in that terminal. To also delete the stored logs, run `docker compose down -v`.

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
  models.py       the common log format
  simulator/      background noise and one file per attack scenario
  tests/
frontend/         the React dashboard
docs/             plan, decisions and learning notes
```

## Next steps

Ideas outside the current phase are parked here until Phase 6 is done.

- A "Clear logs" button, so a demo can start from an empty table without `docker compose down -v`.
- Paging through logs older than the newest 200.
- `npm audit` reports 4 moderate issues in `minimatch`, pulled in by the `shadcn` command-line tool. It is used only while building and is not shipped to the browser. Recheck in the Phase 6 security scan.
- Starlette's test client now prefers `httpx2` over `httpx` (a deprecation warning in the test run). Switch once that is settled.

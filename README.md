# AccessAudit — Backend

FastAPI backend that scans a URL for accessibility (WCAG) violations
using Playwright + axe-core, and for common passive security
misconfigurations (headers, cookies, TLS, mixed content). Runs on
SQLite, so there's nothing else to install to try it locally.

## Folder structure

```
backend/
├── app/
│   ├── main.py                        # FastAPI app, all routes
│   ├── database.py                    # SQLite + SQLAlchemy session setup
│   ├── models.py                      # ScanJob, Violation, SecurityFinding tables
│   ├── schemas.py                     # Pydantic request/response models
│   ├── websocket_manager.py           # tracks live progress connections
│   └── services/
│       ├── accessibility_service.py   # Playwright + axe-core scan logic
│       ├── security_service.py        # headers/cookies/TLS/etc. checks
│       └── scan_orchestrator.py       # runs both scans as one background job
├── requirements.txt
├── .env.example
└── accessaudit.db                     # created automatically on first run
```

## Setup

**1. Create a virtual environment and install dependencies**

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**2. Install the Playwright browser (one-time, downloads Chromium)**

```bash
playwright install chromium
```

**3. Run the server**

```bash
uvicorn app.main:app --reload --port 8000
```

The API is now live at `http://localhost:8000`. You can check it's
working by opening `http://localhost:8000/docs` — FastAPI's
auto-generated interactive API docs, where you can trigger a scan
directly without the frontend.

## How a scan works (for your own reference)

1. `POST /scan` with `{ "url": "https://example.com" }` — creates a
   job in SQLite, returns a `job_id` immediately, and kicks off the
   real scan as a background task.
2. The background task launches headless Chromium (Playwright),
   loads the real page, injects axe-core, and separately runs the
   passive security checks (`httpx` for headers/cookies, Python's
   `ssl` module for TLS).
3. Progress is pushed live over `ws://localhost:8000/ws/scan/{job_id}`.
4. Once done, `GET /scan/{job_id}/results` returns the full violation
   list, security findings, and both scores.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/scan` | Start a new scan for a URL |
| GET | `/scan/{job_id}/status` | Poll current job status (fallback if WebSocket drops) |
| GET | `/scan/{job_id}/results` | Full results once completed |
| GET | `/scans` | List the last 50 scans |
| WS | `/ws/scan/{job_id}` | Live progress stream |

## Notes

- CORS is currently locked to `http://localhost:4200` (the Angular
  dev server) in `main.py` — update `allow_origins` there if you
  deploy the frontend elsewhere.
- Security checks are intentionally **passive only** (reading
  headers, checking TLS config) — no injection or exploitation
  testing. See `security_service.py`'s docstring for the reasoning.
- SQLite is used for zero-setup local development. Swapping to
  Postgres later only requires changing `DATABASE_URL` in
  `database.py` — the SQLAlchemy models don't need to change.

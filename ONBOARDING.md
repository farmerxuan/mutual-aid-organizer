# Onboarding: Dev Quick Start

Purpose
- Help new contributors run the project locally, verify core workflows, and make small safe changes.

Project overview
- Stack: Flask + SQLite + SQLAlchemy. PII encrypted with AES-GCM (`crypto.py`).
- Web UI: Bootstrap + vanilla JS in `templates/` and `static/app.js`.
- Dev-friendly run options: Docker Compose (recommended) or local Python virtualenv.

Important files
- `app.py` — main server, routes, CLI commands.
- `crypto.py` — encryption, phone normalization, phone hashing.
- `templates/`, `static/` — frontend files.
- `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh` — container deployment.
- `run-docker-windows.ps1` — Windows helper to create `.env` and start Docker.
- `tests/smoke_test.py` — pytest smoke checks.

Quick start (recommended: Docker)
1. From project root, run the Windows helper or create `.env` manually:

   - Windows helper:

     ```powershell
     .\run-docker-windows.ps1
     ```

   - Or create `.env` with `ADMIN_USER`, `ADMIN_PASS`, and optional `SECRET_KEY`, then:

     ```bash
     docker compose up -d --build
     ```

2. Visit http://localhost:5000 and log in with the admin credentials from `.env`.

Quick start (local Python)
1. Create a venv and install dependencies:

   ```powershell
   python -m venv .venv
   .venv\Scripts\python -m pip install --upgrade pip
   .venv\Scripts\python -m pip install -r requirements.txt
   ```

2. Set `SECRET_KEY` (base64 or hex 32-byte key) in your environment, then init DB and create a user:

   ```powershell
   .venv\Scripts\python -m flask --app app init-db
   .venv\Scripts\python -m flask --app app create-user
   .venv\Scripts\python -m flask --app app run --host=127.0.0.1 --port=5000
   ```

Smoke checks to run after setup
- Intake a participant (POST `/intake`) with Basic Auth — must include `phone`.
- Submit the same phone (or a short local variant) and verify it is rejected (409).
- GET `/volunteer/list` as a volunteer to see anonymized entries.
- POST `/export/identifying` as admin with `{"confirm":true}` to get identifying CSV and confirm the action appears in `/admin/export-logs`.

Developer workflow
- Branch from `main` for features/fixes. Open PRs using the repository PR template.
- Run `pytest` locally (or rely on CI) before opening a PR.
- Keep secrets out of source control; use `.env` or Docker secrets.

Notes & Risks
- `SECRET_KEY` must be preserved to decrypt existing PII — do not rotate casually.
- This prototype uses Basic Auth; run behind HTTPS for public deployments.
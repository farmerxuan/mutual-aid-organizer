# Resource Organizing Prototype

Minimal Flask + SQLite prototype for anonymized participant intake and role-based access.

Getting started (non-technical quick steps)

1) Recommended: Docker (easiest)
- If you have Docker Desktop installed, open PowerShell in this project folder and run the helper script:

	```powershell
	.\run-docker-windows.ps1
	```

	The script will interactively create a `.env` with `ADMIN_USER` and `ADMIN_PASS` and optionally generate a `SECRET_KEY`, then build and start the app. After it finishes the site will be available at http://localhost:5000

2) Without Docker — local Python (for more technical users)
- Create a 32-byte AES key and set `SECRET_KEY` in your environment. Example (PowerShell):

	```powershell
	$key = [System.Convert]::ToBase64String((1..32 | ForEach-Object {Get-Random -Maximum 256 -AsByte}) -as [byte[]])
	$env:SECRET_KEY = $key
	```

- Create a virtualenv and install requirements:

	```powershell
	python -m venv .venv
	.venv\Scripts\python -m pip install --upgrade pip
	.venv\Scripts\python -m pip install -r requirements.txt
	```

- Initialize DB and create an admin user (interactive):

	```powershell
	.venv\Scripts\python -m flask --app app init-db
	.venv\Scripts\python -m flask --app app create-user
	.venv\Scripts\python -m flask --app app run --host=127.0.0.1 --port=5000
	```

How to use the app (core endpoints)
- `POST /intake` with Basic Auth to add participants. JSON body should include `phone` and optional `name`, `address`, `notes`, `items`, `status`.
- `GET /volunteer/list` returns anonymized list (requires auth).
- `POST /volunteer/lookup` with `anon_id` (coordinator role) returns identifying PII.
- `POST /status/update` to change status.
- `/export/anonymized` and `/export/identifying` for CSV exports (coordinator/admin roles respectively). The identifying export requires a POST with `{"confirm":true}` and is audited.

Where data is stored
- The SQLite DB is stored at `./data/data.db` when using Docker Compose (or `data.db` in the project root for local runs). Keep the `SECRET_KEY` consistent to avoid losing access to encrypted PII.

Security notes
- Keep `SECRET_KEY` secret. Rotate and store in a password manager.
- This prototype uses HTTP Basic Auth and is intended for small teams; run behind HTTPS in production.

More detailed deployment instructions: see `DEPLOY.md`.

Hosting (single authoritative instance)
- If one person (Admin A) will host the app and DB for the team, see `ADMIN_HOSTING.md` for a concise plan, TLS/reverse-proxy notes, backups, and runbook commands.

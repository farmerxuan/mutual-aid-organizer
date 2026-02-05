# Mutual Aid Organizer Prototype

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

  Securely generate a 32‑byte key and export it to the current PowerShell session:

  ```powershell
  # generate 32 random bytes (secure RNG), base64-encode, and set SECRET_KEY for this session
  $bytes = New-Object 'System.Byte[]' 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $key = [Convert]::ToBase64String($bytes)
  $env:SECRET_KEY = $key
  Write-Output "SECRET_KEY set (base64): $key"
  ```

  Or use the bundled Python (recommended) to generate and set the key in PowerShell:

  ```powershell
  $env:SECRET_KEY = & .venv\Scripts\python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
  Write-Output "SECRET_KEY set (base64): $env:SECRET_KEY"
  ```

  To persist the key for Docker/docker-compose or future shells, add it to a `.env` file in the project root:

  ```powershell
  Set-Content -Path .env -Value "SECRET_KEY=$env:SECRET_KEY"
  ```

  Notes:
  - Use the same `SECRET_KEY` whenever you restart the app to be able to decrypt existing PII.
  - In production, store `SECRET_KEY` securely (secrets manager, environment injection), do not commit `.env` to source control.

- Create a virtualenv and install requirements:

	```powershell
	python -m venv .venv
	.venv\Scripts\python -m pip install --upgrade pip
	.venv\Scripts\python -m pip install -r requirements.txt
	```

- Initialize DB and create an admin user (interactive):

	```powershell
	.venv\Scripts\python -m flask --app app init-db
	# Create initial admin non-interactively (preferred for automation):
	$env:ADMIN_USER='admin'
	$env:ADMIN_PASS='change-me'
	.venv\Scripts\python -m flask --app app create-admin-from-env
	# Or interactively:
	.venv\Scripts\python -m flask --app app create-user
	# Run the server:
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

## Invites and password resets

**Admins create invites** (recommended over sending plaintext passwords):
- Use the admin UI at `/ui/users` to send invites with optional email delivery.
- Or use the API: `POST /admin/invite` with `username`, optional `email`, `role`, and `expires_in` (days).
  
  **With email configured:**
  ```bash
  curl -u admin:ADMIN_PASS -H "Content-Type: application/json" -X POST http://localhost:5000/admin/invite \
    -d '{"username":"jane","email":"jane@example.com","role":"volunteer","expires_in":7}'
  ```
  User receives an email with the claim link.

  **Without email (dev mode):**
  ```bash
  curl -u admin:ADMIN_PASS -H "Content-Type: application/json" -X POST http://localhost:5000/admin/invite \
    -d '{"username":"jane","role":"volunteer","dev_mode":true}'
  ```
  API returns the invite link and token; admin shares the link securely.

**Users reset forgotten passwords:**
- Use the web UI or API: `POST /password-reset` with `username` and optional `email`.
  
  ```bash
  curl -X POST -H "Content-Type: application/json" -d '{"username":"jane","email":"jane@example.com"}' \
    http://localhost:5000/password-reset
  ```

**Email configuration (optional):**
- To enable automatic email sending, set environment variables:

  ```
  MAIL_SERVER=smtp.gmail.com
  MAIL_PORT=587
  MAIL_USE_TLS=true
  MAIL_USERNAME=your-email@gmail.com
  MAIL_PASSWORD=your-app-password
  MAIL_DEFAULT_SENDER=noreply@yourorg.com
  ```

  Common providers:
  - **Gmail:** Use an app password (not your account password); enable 2FA first.
  - **SendGrid/Mailgun:** Use their SMTP endpoints.
  - **Self-hosted mail:** Use your Postfix/Exim settings.

  If `MAIL_SERVER` is not set, invites and resets are available via API/link sharing but email is not sent.

- All invite and reset actions are recorded in the admin audit log (`/ui/export-logs`).

## Admin UI — User Management

The admin interface at `/ui/users` provides a dashboard for managing volunteers and coordinators. You can:

- **Send invitation links** — create a new account and optionally email a login link (requires email configured).
- **Create users directly** — supply username, password, and role inline.
- **Bulk import from CSV** — upload a CSV with columns `username`, optional `password`, optional `role`. Generated passwords appear in the result dialog.
- **Manage existing users** — search, change roles, or delete users. All actions are audit-logged.
- **Help modal** — click the **?** button next to the search controls for guidance on each method.

**Login and authentication:**

The web UI uses a client-side login modal. After login, a session cookie is created (server-side) so subsequent API calls (fetch with `credentials: 'same-origin'`) authenticate automatically. The system also supports HTTP Basic Auth as a fallback for direct API calls:

```bash
# API call with Basic Auth
curl -u admin:admin123 http://localhost:5000/admin/users
```

**Example workflow:**

1. Open http://localhost:5000/ui/users in your browser.
2. Click **Log In** (top-right button) and enter admin credentials.
3. Use the forms to send invites, create users, or import from CSV.
4. View the audit log at `/ui/export-logs` to see all admin actions.

````

---

## User Guide (for Volunteers & Coordinators)

This section is for non-technical users who just need to use the system.

### Getting Started
- Your admin will give you a login link or send you an invite email.
- If you have an invite link, click it and set your password.
- If you have username/password, click **Log In** at the top-right of any page.

### Main Pages

**Intake (/ui/intake)** � Add a new participant
- Fill in the participant's phone number (required).
- Optionally add name, address, and special items/notes.
- Click **Submit**. You will see a unique anonymous ID (keep this for reference).
- Phone number is checked automatically to prevent duplicates.

**Volunteer List (/ui/volunteer)** � View tasks
- See all participants and their items (food, non-food, custom).
- Click **Show PII** to view full details if you need to contact them (requires coordinator role).
- Use the phone search to look up a specific person by phone number.

**Admin Page (/ui/admin)** � Summary for coordinators/admins
- View all participants in card format.
- Search by phone to find a record quickly.
- Click **Show PII** to see full contact details.
- Download CSV exports:
  - **Anonymized CSV**: Safe to share (no names/phones).
  - **Identifying CSV** (admin only): Full details; requires confirmation (action is logged).

### Common Tasks
- **Look up by phone**: Go to Admin page, enter phone, click Search.
- **Download anonymized list**: Click **Download anonymized CSV**, open in Excel.
- **Reset password**: Ask admin to send a password reset link.

### Tips
- Participant IDs look like random codes. Use these to refer to people in your team.
- All actions are logged for security.
- Never share identifying CSVs carelessly � they contain contact info.

---

## Admin Guide (Setup & Management)

This section is for admins managing the system (minimal/no coding required).

### First Time Setup

**Option 1: Docker (easiest)**
1. Make sure Docker Desktop is installed.
2. Open PowerShell in this project folder.
3. Run: .\run-docker-windows.ps1
4. Follow the prompts to set admin username/password.
5. Visit http://localhost:5000

**Option 2: Local Python**
1. Open PowerShell in the project folder.
2. Run: python -m venv .venv
3. Run: .venv\Scripts\python -m pip install -r requirements.txt
4. Run: .venv\Scripts\python -m flask --app app init-db
5. Run: .venv\Scripts\python -m flask --app app create-user (enter username, password, admin)
6. Run: .venv\Scripts\python -m flask --app app run --host=127.0.0.1 --port=5000
7. Visit http://localhost:5000

### Managing Users

**Send invites (recommended):**
1. Go to /ui/users and log in.
2. Enter username, optional email, select role, click **Send Invite**.
3. Share the link with the user.

**Create user directly:**
1. Go to /ui/users.
2. Enter username, password, role, click **Create**.

**Bulk import from CSV:**
1. Prepare CSV: username,password,role
2. Upload at /ui/users under **Bulk import users (CSV)**.

**Manage existing users:**
1. Go to /ui/users, search by username, change role or delete.

### Email Setup (Optional)

Add to .env file:
- MAIL_SERVER=smtp.gmail.com
- MAIL_PORT=587
- MAIL_USE_TLS=true
- MAIL_USERNAME=your-email@gmail.com
- MAIL_PASSWORD=your-app-password
- MAIL_DEFAULT_SENDER=noreply@yourorg.com

Then restart the app. Invites will email automatically.

### Exports & Auditing

- Visit /ui/export-logs to see who exported what and when.
- All admin actions are logged (user creation, role changes, resets).

### Security Reminders
- Keep SECRET_KEY secret.
- Do not commit .env to Git.
- Invite links expire after 7 days.
- Password reset links expire after 2 hours.
- Check audit logs regularly.


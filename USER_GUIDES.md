# User Guides for the Non-Technical

This document is for volunteers, coordinators, and admins who want to use the system without writing code.

---

## User Guide (for Volunteers & Coordinators)

This section is for non-technical users who just need to use the system.

### Getting Started
- Your admin will give you a login link or send you an invite email.
- If you have an invite link, click it and set your password.
- If you have username/password, click **Log In** at the top-right of any page.

### Main Pages

**Intake (/ui/intake)** - Add a new participant
- Fill in the participant's phone number (required).
- Optionally add name, address, and special items/notes.
- Click **Submit**. You will see a unique anonymous ID (keep this for reference).
- Phone number is checked automatically to prevent duplicates.

**Volunteer List (/ui/volunteer)** - View tasks
- See all participants and their items (food, non-food, custom).
- Click **Show PII** to view full details if you need to contact them (requires coordinator role).
- Use the phone search to look up a specific person by phone number.

**Admin Page (/ui/admin)** - Summary for coordinators/admins
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
- Never share identifying CSVs carelessly - they contain contact info.

---

## Admin Guide (Setup & Management)

This section is for admins managing the system (minimal/no coding required).

### First Time Setup

**Option 1: Docker (easiest)**
1. Make sure Docker Desktop is installed.
2. Open PowerShell in this project folder.
3. Run: `.\run-docker-windows.ps1`
4. Follow the prompts to set admin username/password.
5. Visit http://localhost:5000

**Option 2: Local Python**
1. Open PowerShell in the project folder.
2. Run: `python -m venv .venv`
3. Run: `.venv\Scripts\python -m pip install -r requirements.txt`
4. Run: `.venv\Scripts\python -m flask --app app init-db`
5. Run: `.venv\Scripts\python -m flask --app app create-user` (enter username, password, admin)
6. Run: `.venv\Scripts\python -m flask --app app run --host=127.0.0.1 --port=5000`
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
1. Prepare CSV: `username,password,role`
2. Upload at /ui/users under **Bulk import users (CSV)**.

**Manage existing users:**
1. Go to /ui/users, search by username, change role or delete.

### Email Setup (Optional)

Add to `.env` file:
```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@yourorg.com
```

Then restart the app. Invites will email automatically.

### Exports & Auditing

- Visit /ui/export-logs to see who exported what and when.
- All admin actions are logged (user creation, role changes, resets).

### Security Reminders
- Keep `SECRET_KEY` secret.
- Do not commit `.env` to Git.
- Invite links expire after 7 days.
- Password reset links expire after 2 hours.
- Check audit logs regularly.


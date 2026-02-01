# Hosting: Single authoritative instance (Admin A)

This document shows a concise plan and concrete steps for one person ("Admin A") to host the authoritative web app + database so other collaborators (admins, coordinators, volunteers) can access it via the web without running their own DB.

Overview
- Admin A runs the Flask app and the SQLite database on a single server or VM.
- The app is exposed via HTTPS (reverse proxy) and other team members use the site URL to interact with the system.
- Admin A is responsible for backups, the `SECRET_KEY`, and creating/removing user accounts.

Recommended components
- App container: the project runs via `docker compose` (see `docker-compose.yml`).
- Reverse proxy with TLS: use Caddy or nginx + Certbot to obtain and renew HTTPS certificates.
- Persistent data volume: map `./data` on the host to `/app/data` in the container to persist `data.db`.

Quick deployment steps (Admin A)

1. Clone repo on the host and create `.env` with credentials and secret

```bash
git clone https://github.com/yourusername/mutual-aid-organizer.git
cd mutual-aid-organizer
cat > .env <<'EOF'
ADMIN_USER=admin
ADMIN_PASS=strongpassword
# SECRET_KEY should be a 32-byte value (base64 or hex). If omitted, the container will generate one,
# but you should persist it to avoid losing access to encrypted PII.
# SECRET_KEY=...
EOF
```

2. Start the app with Docker Compose

```bash
docker compose up -d --build
```

3. Configure HTTPS (example with Caddy)

Create a `Caddyfile` that points to the app container (Caddy obtains TLS automatically):

```
your.domain.example {
  reverse_proxy 127.0.0.1:5000
}
```

Run Caddy (or configure nginx + certbot) so `https://your.domain.example` serves the app.

4. Create additional users

On the host, create coordinator/volunteer accounts as needed:

```bash
docker compose exec app flask --app app create-user
```

Or create non-interactively before first start:

```bash
ADMIN_USER=alice ADMIN_PASS=alicepass docker compose run --rm app flask --app app create-admin-from-env
```

Backups & recovery
- Backup `./data/data.db` regularly (e.g., nightly) by copying it to a backup folder or offsite storage.
- Example simple backup command:

```bash
mkdir -p backups
cp data/data.db backups/data-$(date +%F-%H%M).db
```

Security & operational notes
- Keep the `SECRET_KEY` private and backed up. If changed or lost, previously encrypted PII cannot be decrypted.
- Use HTTPS and a firewall. Expose only ports 80/443 publicly; the app can run on localhost:5000 behind the proxy.
- Rotate admin passwords when team members change.
- Review `ExportLog` periodically for identifying exports.

Scaling notes
- For light usage and small teams, SQLite is acceptable. For heavier loads or concurrent writes, migrate to PostgreSQL and update `SQLALCHEMY_DATABASE_URI` in `app.py`.

Quick runbook (copy/paste)

```bash
# Start
docker compose up -d --build

# Stop
docker compose down

# Backup
cp data/data.db backups/data-$(date +%F-%H%M).db

# Create a user on the host
docker compose exec app flask --app app create-user
```

If you want, I can add a sample `Caddyfile`, a small backup script, and a one-line restore command.

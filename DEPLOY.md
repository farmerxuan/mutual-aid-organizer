**Quick Docker deployment (for non-technical users)**

This project can be run with Docker and Docker Compose. The instructions below create a container that runs the Flask application and stores the SQLite database in a local `./data` folder so data persists across restarts.

Prerequisites
- Install Docker Desktop (Windows/macOS) or Docker Engine + docker-compose (Linux).

Quick start (recommended)

1. From the project root (where `docker-compose.yml` lives), create a `.env` file with at least `ADMIN_USER` and `ADMIN_PASS` so an admin account is created automatically. Optionally set a `SECRET_KEY` to keep encryption consistent between restarts.

Example `.env` (create this file in the project root):

```
ADMIN_USER=admin
ADMIN_PASS=your-strong-password
# SECRET_KEY is optional; if omitted the container will generate one and print it on first run.
# SECRET_KEY=<base64-or-hex-encoded-32-byte-key>
```

2. Build and run with Docker Compose:

```bash
docker compose up -d --build
```

3. Open the app in a browser at http://localhost:5000

Notes and recovery
- The SQLite DB is stored locally at `./data/data.db` (created automatically). Do not delete it unless you want a fresh database.
- If you don't provide `SECRET_KEY`, the container will generate one on first start and print it in the container logs; copy and persist it into your `.env` if you want to be able to recreate the container and retain access to PII.
- To see logs: `docker compose logs -f` or `docker logs -f <container_id>`
- To stop: `docker compose down`

Advanced: Recreating the container
- If you stop and remove the container but keep `./data`, the app will reuse the same DB and data.
- If you want to rotate `SECRET_KEY` you must re-encrypt PII manually; do not change `SECRET_KEY` unless you understand its impact.

Security
- This setup is intended for small, trusted teams. For public hosting, run behind a reverse proxy (Nginx) and HTTPS. Store `SECRET_KEY` and admin credentials securely (don't commit `.env` to source control).

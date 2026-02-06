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

# Optional: Email configuration for invites and password resets
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@yourorg.com
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

Email configuration
- If you set `MAIL_SERVER`, the app will send invites and password-reset links via email automatically.
- Common providers:
  - **Gmail:** Create an app password after enabling 2FA, then use that password in `MAIL_PASSWORD`.
  - **SendGrid / Mailgun / AWS SES:** Use their SMTP endpoints and API credentials.
  - **Self-hosted:** Use your organizational Postfix or Exim SMTP settings.
- If `MAIL_SERVER` is not set, invites and resets work via web link but are not emailed.

---

## Remote Access & Self-Hosting

By default, the app listens on `127.0.0.1:5000` (localhost only). To allow access from other machines, follow these steps:

### Option 1: Direct network access (simple, for trusted networks)

1. **Find your host machine's IP address:**
   - Windows: Open PowerShell and run `ipconfig`. Look for "IPv4 Address" (e.g., `192.168.1.100`).
   - Linux: Run `hostname -I`.

2. **Update `.env` to expose the app:**
   Add or modify the `FLASK_HOST` variable:
   ```
   FLASK_HOST=0.0.0.0
   ```
   This tells Flask to listen on all network interfaces.

3. **Restart the app:**
   ```bash
   docker compose down
   docker compose up -d
   ```

4. **Access from other machines:**
   Open a browser on another machine and go to:
   ```
   http://<your-host-ip>:5000
   ```
   Example: `http://192.168.1.100:5000`

**Security notes for direct access:**
- This is suitable for **small, trusted teams on a private network only**.
- The app uses HTTP (not HTTPS) by default, so credentials are sent unencrypted. Use only on trusted networks.
- Anyone with access to the port can view/edit participant data. Restrict network access via firewall.

### Option 2: Reverse proxy with HTTPS (recommended for broader access)

For secure remote access (e.g., over the internet), use a reverse proxy like Nginx or Apache to add HTTPS.

#### Setup with Nginx (Linux example):

1. **Install Nginx:**
   ```bash
   sudo apt-get install nginx
   ```

2. **Create an Nginx config** at `/etc/nginx/sites-available/mutual-aid`:
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;  # Replace with your domain
       
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

3. **Enable the site:**
   ```bash
   sudo ln -s /etc/nginx/sites-available/mutual-aid /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

4. **Add HTTPS with Let's Encrypt (free):**
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```
   Certbot will automatically update your Nginx config to use HTTPS.

5. **Access the app:**
   ```
   https://yourdomain.com
   ```

#### Docker Compose setup with Nginx:

Alternatively, use a Docker Compose network and add an Nginx service:

```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      FLASK_HOST: app  # Internal Docker hostname
      ...
    volumes:
      - ./data:/app/data

  nginx:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - app
```

### Option 3: Hosting on a cloud provider (AWS, Digital Ocean, Linode, etc.)

1. **Provision a server** (e.g., Ubuntu 20.04 VM).
2. **Install Docker and Docker Compose** on the server.
3. **Copy the project** to the server (via `git clone` or `scp`).
4. **Set up `.env`** with strong credentials and optional `SECRET_KEY`.
5. **Run with Docker Compose:**
   ```bash
   docker compose up -d
   ```
6. **Set up a domain and HTTPS** (see Nginx setup above or use a managed service like AWS ALB).

### Firewall & port forwarding

- **Private network:** Restrict access via firewall rules to only trusted IPs/ranges.
- **Internet-facing:** Use a firewall to allow only HTTP (80) and HTTPS (443). Block direct access to port 5000.
- **Port forwarding (home server):** If hosting at home, forward ports 80/443 on your router to your server's internal IP.

### Security checklist for remote access

- [ ] Use HTTPS in production (not HTTP).
- [ ] Store `.env` securely; do not commit it to version control.
- [ ] Keep `SECRET_KEY` private and consistent across restarts.
- [ ] Use strong admin credentials (`ADMIN_PASS`).
- [ ] Enable email invites so users set their own passwords (do not share plaintext passwords).
- [ ] Run behind a reverse proxy and firewall for public access.
- [ ] Regularly audit logs (`/ui/export-logs`) for suspicious activity.
- [ ] Consider rate-limiting logins to prevent brute-force attacks.
- [ ] Update Docker images and dependencies regularly.

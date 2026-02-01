#!/bin/sh
set -e

# If SECRET_KEY not set, generate a random one and print it (user should persist it)
if [ -z "$SECRET_KEY" ]; then
  echo "SECRET_KEY not set; generating a temporary key — save this to reuse later"
  SECRET_KEY=$(python - <<'PY'
import base64, os
print(base64.b64encode(os.urandom(32)).decode())
PY
)
  export SECRET_KEY
  echo "SECRET_KEY=$SECRET_KEY"
fi

# Ensure data directory exists
mkdir -p /app/data

# Initialize DB if missing
if [ ! -f /app/data/data.db ]; then
  echo "Initializing database..."
  flask init-db
fi

# Create admin user from env if provided
if [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ]; then
  echo "Ensuring admin user exists..."
  flask create-admin-from-env || true
fi

echo "Starting gunicorn on :5000"
exec gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 "app:app"

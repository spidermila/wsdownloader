#!/usr/bin/env bash
set -euo pipefail

# Ensure paths exist
mkdir -p /downloads /data

# Initialize DB schema once before web starts
python - <<'PY'
from app import init_db
init_db()
print("DB initialized")
PY

# Start web (Gunicorn, production-ready)
# Workers/threads can be tuned via env vars
: "${WEB_CONCURRENCY:=1}"
: "${WEB_THREADS:=2}"
gunicorn "app:app" \
  --bind 0.0.0.0:5000 \
  --no-control-socket \
  --workers "${WEB_CONCURRENCY}" \
  --threads "${WEB_THREADS}" \
  --logger-class "app.MyGunicornLogger" \
  --access-logfile '-' \
  --access-logformat '%(t)s [gunicorn] %(p)s %(h)s %(l)s %(u)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"' \
  --log-level "info" \
  --error-logfile '-' &
APP_PID=$!

# Start downloader
python /app/downloader.py &
DL_PID=$!

term_handler() {
  echo "Stopping..."
  kill -TERM "$APP_PID" "$DL_PID" 2>/dev/null || true
  wait "$APP_PID" "$DL_PID" 2>/dev/null || true
  exit 143
}
trap term_handler SIGTERM SIGINT

# Monitor both; if one dies, stop the other
while true; do
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "gunicorn stopped; terminating downloader..."
    kill -TERM "$DL_PID" 2>/dev/null || true
    wait "$DL_PID" 2>/dev/null || true
    exit 1
  fi
  if ! kill -0 "$DL_PID" 2>/dev/null; then
    echo "downloader stopped; terminating web..."
    kill -TERM "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
    exit 1
  fi
  sleep 2
done

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

# Start web (Gunicorn + gevent for proper async concurrency with Flask-SocketIO)
# WEB_CONCURRENCY controls the number of gevent workers (each handles thousands of
# concurrent greenlets, so 1-2 workers is typically enough).
: "${WEB_CONCURRENCY:=1}"
: "${LOG_LEVEL:=INFO}"

gunicorn "app:app" \
  --bind 0.0.0.0:5000 \
  --no-control-socket \
  --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
  --workers "${WEB_CONCURRENCY}" \
  --log-level "${LOG_LEVEL,,}" \
  --access-logfile '-' \
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

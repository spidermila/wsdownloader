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

# Read (or generate) the aria2 RPC secret so it is shared with the daemon
# and with app.py / downloader.py which read it via torrent.read_or_create_secret().
ARIA2_RPC_SECRET="${ARIA2_RPC_SECRET:-$(python -c 'from torrent import read_or_create_secret; print(read_or_create_secret())')}"
export ARIA2_RPC_SECRET
: "${ARIA2_LISTEN_PORT:=51413}"
: "${ARIA2_ENABLE_DHT:=true}"

# aria2 refuses to start if --input-file points at a missing path.
touch "${DATA_DIR:-/data}/aria2.session"

# Persisted global speed limits (bytes/s, 0 = unlimited) from the settings
# table; read once at startup and passed to aria2. Runtime changes are pushed
# via aria2.changeGlobalOption by app.py.
eval "$(python - <<'PY'
import os, sqlite3, sys
db = os.environ.get('DB_PATH') or f"{os.environ.get('DATA_DIR', '/data')}/downloader.db"
dl = ul = 0
try:
    c = sqlite3.connect(db)
    try:
        r = c.execute(
            'SELECT torrent_max_dl_bps, torrent_max_ul_bps '
            'FROM settings WHERE id = 1'
        ).fetchone()
        if r:
            dl, ul = int(r[0] or 0), int(r[1] or 0)
    finally:
        c.close()
except sqlite3.Error as exc:
    print(f'WARN: could not read torrent speed limits from {db}: {exc}',
          file=sys.stderr)
print(f'ARIA2_MAX_DL_BPS={dl}; ARIA2_MAX_UL_BPS={ul}')
PY
)"
export ARIA2_MAX_DL_BPS ARIA2_MAX_UL_BPS

start_aria2() {
  aria2c \
    --enable-rpc=true \
    --rpc-listen-all=false \
    --rpc-listen-port=6800 \
    --rpc-secret="${ARIA2_RPC_SECRET}" \
    --dir="${DOWNLOADS_DIR:-/downloads}" \
    --continue=true \
    --auto-file-renaming=false \
    --save-session="${DATA_DIR:-/data}/aria2.session" \
    --save-session-interval=30 \
    --input-file="${DATA_DIR:-/data}/aria2.session" \
    --bt-save-metadata=false \
    --rpc-save-upload-metadata=false \
    --enable-dht="${ARIA2_ENABLE_DHT}" \
    --enable-peer-exchange=true \
    --bt-enable-lpd=true \
    --listen-port="${ARIA2_LISTEN_PORT}" \
    --dht-listen-port="${ARIA2_LISTEN_PORT}" \
    --seed-time=0 \
    --max-connection-per-server=8 \
    --split=8 \
    --max-overall-download-limit="${ARIA2_MAX_DL_BPS}" \
    --max-overall-upload-limit="${ARIA2_MAX_UL_BPS}" \
    --daemon=false &
  ARIA_PID=$!
}

# Launch aria2 in RPC mode.  Bound to 127.0.0.1 with a shared secret; the
# BT peer port (51413) is only exposed if the operator publishes it via -p.
start_aria2

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
  --timeout 120 \
  --log-level "${LOG_LEVEL,,}" \
  --access-logfile '-' \
  --error-logfile '-' &
APP_PID=$!

# Start downloader
python /app/downloader.py &
DL_PID=$!

term_handler() {
  echo "Stopping..."
  kill -TERM "$APP_PID" "$DL_PID" "$ARIA_PID" 2>/dev/null || true
  wait "$APP_PID" "$DL_PID" "$ARIA_PID" 2>/dev/null || true
  exit 143
}
trap term_handler SIGTERM SIGINT

# Monitor gunicorn + downloader; if one dies, stop the others.  aria2 is
# allowed to crash and be restarted independently (rare, and the DL loop
# tolerates a brief RPC outage).
restart_aria2() {
  echo "aria2 stopped; restarting..."
  touch "${DATA_DIR:-/data}/aria2.session"
  start_aria2
}

while true; do
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "gunicorn stopped; terminating downloader and aria2..."
    kill -TERM "$DL_PID" "$ARIA_PID" 2>/dev/null || true
    wait "$DL_PID" "$ARIA_PID" 2>/dev/null || true
    exit 1
  fi
  if ! kill -0 "$DL_PID" 2>/dev/null; then
    echo "downloader stopped; terminating web and aria2..."
    kill -TERM "$APP_PID" "$ARIA_PID" 2>/dev/null || true
    wait "$APP_PID" "$ARIA_PID" 2>/dev/null || true
    exit 1
  fi
  if ! kill -0 "$ARIA_PID" 2>/dev/null; then
    restart_aria2
  fi
  sleep 2
done

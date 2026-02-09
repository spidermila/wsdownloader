#!/usr/bin/env bash
set -euo pipefail

# HTTP check
if ! curl -fsS --max-time 2 http://127.0.0.1:5000/health >/dev/null; then
  echo "Flask (gunicorn) not responding"
  exit 1
fi

# Process checks
if ! pgrep -f "gunicorn.*app:app" >/dev/null; then
  echo "gunicorn (app:app) not running"
  exit 1
fi
if ! pgrep -f "downloader.py" >/dev/null; then
  echo "downloader.py not running"
  exit 1
fi
echo "OK"

#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="downloader:latest"
CONTAINER_NAME="downloader"

# If a previous container exists, remove it
if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

docker run -d \
  --restart unless-stopped \
  --name "${CONTAINER_NAME}" \
  --user "1000:1000" \
  --network proxy \
  --dns 192.168.111.5 \
  -p 5555:5000 \
  -e WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}" \
  -e WEB_THREADS="${WEB_THREADS:-4}" \
  -v "/mnt/usb/filmy:/downloads" \
  -v "${HOME}/docker/downloader/data:/data" \
  "${IMAGE_TAG}"

echo "Container ${CONTAINER_NAME} is starting."
echo "Open http://localhost:5555"

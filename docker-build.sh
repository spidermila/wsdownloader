#!/usr/bin/env bash
set -euo pipefail

# Build image tag (change if you like)
IMAGE_TAG="downloader:latest"

cd ${HOME}/docker/wsdownloader
docker build -t "${IMAGE_TAG}" .
echo "Built ${IMAGE_TAG}"

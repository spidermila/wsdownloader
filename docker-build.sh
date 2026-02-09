#!/usr/bin/env bash
set -euo pipefail

# Build image tag (change if you like)
IMAGE_TAG="wsdownloader:latest"

cd ${HOME}/docker/wsdownloader
docker build -t "${IMAGE_TAG}" .
echo "Built ${IMAGE_TAG}"

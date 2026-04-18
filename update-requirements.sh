#!/usr/bin/env bash
set -euo pipefail

# Recompile requirements/*.txt from requirements/*.in using Python 3.13 (matches Docker).
# Pass --upgrade to bump all packages to the latest compatible versions.
# Without --upgrade, versions are kept stable unless constrained deps force a change.
#
# Usage:
#   ./update-requirements.sh           # recompile, keep versions stable
#   ./update-requirements.sh --upgrade # recompile and bump all to latest

UPGRADE_FLAG="${1:-}"
PYTHON_IMAGE="python:3.13-slim"
REQ_DIR="$(cd "$(dirname "$0")/requirements" && pwd)"

echo "Using ${PYTHON_IMAGE} to compile requirements..."

docker run --rm \
    -v "${REQ_DIR}:/req" \
    "${PYTHON_IMAGE}" \
    bash -c "
        pip install pip-tools -q
        pip-compile --generate-hashes ${UPGRADE_FLAG} --output-file /req/prod.txt /req/prod.in
        pip-compile --generate-hashes ${UPGRADE_FLAG} --output-file /req/dev.txt /req/dev.in
        chown $(id -u):$(id -g) /req/prod.txt /req/dev.txt
    "

echo "Done. Review changes in requirements/prod.txt and requirements/dev.txt before committing."

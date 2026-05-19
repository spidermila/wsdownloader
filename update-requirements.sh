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

# Extract "lowercase_name version" pairs from a compiled requirements file
_extract() {
    grep -E '^[a-zA-Z][a-zA-Z0-9_.+-]*==[0-9]' "$1" \
        | sed 's/ \\$//' \
        | awk -F'==' '{printf "%s %s\n", tolower($1), $2}'
}

# Print a human-readable diff between two compiled requirements files
show_diff() {
    local label="$1" old_file="$2" new_file="$3"

    declare -A old_v new_v
    while read -r name ver; do old_v["$name"]="$ver"; done < <(_extract "$old_file")
    while read -r name ver; do new_v["$name"]="$ver"; done < <(_extract "$new_file")

    local -a updated=() added=() removed=() same=()

    for name in "${!new_v[@]}"; do
        if [[ -v old_v["$name"] ]]; then
            if [[ "${old_v[$name]}" == "${new_v[$name]}" ]]; then
                same+=("$name")
            else
                updated+=("  ↑  $name  ${old_v[$name]} → ${new_v[$name]}")
            fi
        else
            added+=("  +  $name==${new_v[$name]}")
        fi
    done

    for name in "${!old_v[@]}"; do
        [[ -v new_v["$name"] ]] || removed+=("  -  $name==${old_v[$name]}")
    done

    IFS=$'\n' updated=($(sort <<<"${updated[*]-}")); unset IFS
    IFS=$'\n' added=($(sort <<<"${added[*]-}")); unset IFS
    IFS=$'\n' removed=($(sort <<<"${removed[*]-}")); unset IFS

    echo ""
    echo "── ${label} ──────────────────────────────────"
    if [[ ${#updated[@]} -gt 0 ]]; then
        echo "  UPDATED:"
        printf '%s\n' "${updated[@]}"
    fi
    if [[ ${#added[@]} -gt 0 ]]; then
        echo "  NEW:"
        printf '%s\n' "${added[@]}"
    fi
    if [[ ${#removed[@]} -gt 0 ]]; then
        echo "  REMOVED:"
        printf '%s\n' "${removed[@]}"
    fi
    if [[ ${#updated[@]} -eq 0 && ${#added[@]} -eq 0 && ${#removed[@]} -eq 0 ]]; then
        echo "  No changes."
    fi
    echo "  UNCHANGED: ${#same[@]} packages"
}

# Save current state for diffing (handle first run where files may not exist)
TMPDIR_DIFF="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_DIFF"' EXIT

[[ -f "${REQ_DIR}/prod.txt" ]] && cp "${REQ_DIR}/prod.txt" "${TMPDIR_DIFF}/prod.txt.old" || touch "${TMPDIR_DIFF}/prod.txt.old"
[[ -f "${REQ_DIR}/dev.txt" ]]  && cp "${REQ_DIR}/dev.txt"  "${TMPDIR_DIFF}/dev.txt.old"  || touch "${TMPDIR_DIFF}/dev.txt.old"

echo "Using ${PYTHON_IMAGE} to compile requirements..."

docker run --rm \
    -v "${REQ_DIR}:/requirements" \
    "${PYTHON_IMAGE}" \
    bash -c "
        pip install pip-tools -q
        cd /
        pip-compile --generate-hashes ${UPGRADE_FLAG} --output-file requirements/prod.txt requirements/prod.in
        pip-compile --generate-hashes ${UPGRADE_FLAG} --output-file requirements/dev.txt requirements/dev.in
        chown $(id -u):$(id -g) requirements/prod.txt requirements/dev.txt
    "

show_diff "prod" "${TMPDIR_DIFF}/prod.txt.old" "${REQ_DIR}/prod.txt"
show_diff "dev (includes prod)" "${TMPDIR_DIFF}/dev.txt.old" "${REQ_DIR}/dev.txt"

echo ""
echo "Done. Review changes in requirements/prod.txt and requirements/dev.txt before committing."

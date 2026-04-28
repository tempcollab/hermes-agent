#!/usr/bin/env bash
# Setup script for Hermes Agent security audit.
# Pins commit 124da27 and prepares the test environment.

set -euo pipefail

EXPECTED_COMMIT="124da27"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Verify we are running at the expected commit.
ACTUAL_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
if [[ "${ACTUAL_COMMIT}" != "${EXPECTED_COMMIT}"* ]]; then
    echo "[!] WARNING: expected commit ${EXPECTED_COMMIT}, got ${ACTUAL_COMMIT}" >&2
fi

# Create results directory if it does not exist.
mkdir -p "${SCRIPT_DIR}/results"

# Make exploit scripts executable.
chmod +x "${SCRIPT_DIR}/exploits/"*.py 2>/dev/null || true

# Set PYTHONPATH so hermes modules resolve without installing the package.
export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

echo "[setup] PYTHONPATH=${PYTHONPATH}"
echo "[setup] Repo root: ${REPO_ROOT}"
echo "[setup] Commit: ${ACTUAL_COMMIT}"

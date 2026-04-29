#!/usr/bin/env bash
# Teardown script for Hermes Agent security audit.
# Removes marker files and kills any lingering test processes.

set -uo pipefail

echo "[teardown] Removing /tmp/pwned_* and /tmp/chain_* marker files..."
rm -f /tmp/pwned_*.txt /tmp/chain_*.txt

echo "[teardown] Killing any lingering tui_gateway processes..."
pkill -f "tui_gateway.entry" 2>/dev/null || true

echo "[teardown] Done."

#!/usr/bin/env bash
# Thin wrapper: scan static log tails + persistence audit JSON for a session.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
exec python -m scytaledroid.StaticAnalysis.audit "$@"

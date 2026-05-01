#!/usr/bin/env bash
set -euo pipefail

# Deterministic non-account idle capture helper for dynamic paper perturbation.
# Usage:
#   scripts/dynamic/run_idle.sh <package_name> [duration_seconds]
#
# This script keeps the app in foreground and avoids user interaction.

PKG="${1:-}"
DURATION="${2:-180}"

if [[ -z "$PKG" ]]; then
  echo "usage: $0 <package_name> [duration_seconds]" >&2
  exit 2
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
  echo "duration_seconds must be an integer" >&2
  exit 2
fi

echo "[idle] package=$PKG duration=${DURATION}s"
adb shell input keyevent KEYCODE_WAKEUP || true
adb shell am force-stop "$PKG" || true
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null
sleep 2
echo "[idle] collecting..."
sleep "$DURATION"
echo "[idle] done"

#!/usr/bin/env bash
set -euo pipefail

# Deterministic non-account scripted interaction helper for dynamic paper perturbation.
# Usage:
#   scripts/dynamic/run_scripted_interaction.sh <package_name> [duration_seconds]
#
# Script performs a fixed swipe/tap cadence while app is foregrounded.

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

echo "[scripted] package=$PKG duration=${DURATION}s"
adb shell input keyevent KEYCODE_WAKEUP || true
adb shell am force-stop "$PKG" || true
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null
sleep 3

end_ts=$((SECONDS + DURATION))
step=0
while [[ $SECONDS -lt $end_ts ]]; do
  case $((step % 4)) in
    0) adb shell input swipe 500 1700 500 500 350 >/dev/null ;;
    1) adb shell input tap 540 960 >/dev/null ;;
    2) adb shell input swipe 500 500 500 1700 350 >/dev/null ;;
    3) adb shell input tap 900 1700 >/dev/null ;;
  esac
  step=$((step + 1))
  sleep 2
done

echo "[scripted] done"

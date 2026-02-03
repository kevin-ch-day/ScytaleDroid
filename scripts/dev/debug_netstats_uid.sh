#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <serial> <uid> [output_file]"
  exit 1
fi

serial="$1"
uid="$2"
output_file="${3:-netstats_uid_${uid}.txt}"

adb -s "$serial" shell dumpsys netstats --uid "$uid" > "$output_file"
echo "Wrote $output_file"

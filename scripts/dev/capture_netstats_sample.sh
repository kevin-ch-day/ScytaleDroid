#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <serial> [output_file]"
  exit 1
fi

serial="$1"
output_file="${2:-netstats_detail_sample.txt}"

adb -s "$serial" shell dumpsys netstats detail > "$output_file"
echo "Wrote $output_file"

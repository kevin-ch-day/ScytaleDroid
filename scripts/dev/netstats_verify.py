#!/usr/bin/env python3
"""Verify netstats byte extraction for a single package."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DeviceAnalysis.adb import client as adb_client
from scytaledroid.Utils.netstats_collector import NetstatsCollector
from scytaledroid.Utils.netstats_parser import NetstatsParser
from scytaledroid.Utils.process_parsers import resolve_pid_uid


def _resolve_serial(serial: str | None) -> str:
    if serial:
        return serial
    completed = adb_client.run_adb_command(["devices"])
    lines = [line.strip() for line in (completed.stdout or "").splitlines()]
    devices = [line.split()[0] for line in lines if line.endswith("\tdevice")]
    if not devices:
        raise RuntimeError("No adb devices detected. Provide --serial.")
    return devices[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify netstats parsing for a package.")
    parser.add_argument("package", help="Target package name")
    parser.add_argument("--serial", help="ADB device serial")
    parser.add_argument("--debug-out", help="Write debug netstats lines to file")
    args = parser.parse_args()

    serial = _resolve_serial(args.serial)
    uid, _ = resolve_pid_uid(serial, args.package)
    if not uid:
        print("ERROR: unable to resolve UID for package.")
        return 2

    collector = NetstatsCollector()
    parser_impl = NetstatsParser()

    detail = collector.collect_detail(serial)
    if detail.returncode == 0 and detail.stdout:
        sample = parser_impl.parse_detail(detail.stdout, uid)
        if sample.rx_bytes is not None and sample.tx_bytes is not None:
            print(f"detail bytes: rx={sample.rx_bytes} tx={sample.tx_bytes} parse={sample.parse_method}")
            return 0

    uid_output = collector.collect_uid(serial, uid)
    if uid_output.returncode == 0 and uid_output.stdout:
        sample = parser_impl.parse_uid(uid_output.stdout, uid)
        if sample.rx_bytes is not None and sample.tx_bytes is not None:
            print(f"uid bytes: rx={sample.rx_bytes} tx={sample.tx_bytes} parse={sample.parse_method}")
            return 0

    print("WARN: netstats bytes missing. Consider capturing debug output.")
    if args.debug_out:
        destination = Path(args.debug_out)
        output = detail.stdout or uid_output.stdout
        if output:
            parser_impl.write_debug_capture(output, uid=uid, destination=destination)
            print(f"Debug capture written to {destination}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
